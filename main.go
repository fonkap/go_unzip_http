package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
)

const headerLen = 65536

// CDirentry representa la estructura de una entrada del directorio central
type CDirentry struct {
	Signature              uint32
	VersionMadeBy          uint16
	VersionNeeded          uint16
	GeneralPurposeBitFlag  uint16
	CompressionMethod      uint16
	LastModFileTime        uint16
	LastModFileDate        uint16
	Crc32                  uint32
	CompressedSize         uint64
	UncompressedSize       uint64
	FileNameLength         uint16
	ExtraFieldLength       uint16
	FileCommentLength      uint16
	DiskNumberStart        uint16
	InternalFileAttributes uint16
	ExternalFileAttributes uint32
	OffsetLocalHeader      uint64
	FileName               string
}

func getRangeCurl(url string, start int64, n int64) (int, io.ReadCloser, error) {
	rangeHeader := fmt.Sprintf("Range: bytes=%d-%d", start, start+n-1)
	cmd := exec.Command("curl", "-v", "-H", rangeHeader, url)

	stderr, _ := cmd.StderrPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		return 0, nil, err
	}

	scanner := bufio.NewScanner(stderr)
	re := regexp.MustCompile(`HTTP/\d\.\d (\d{3})`)
	statusCode := 0
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			statusCode, _ = strconv.Atoi(matches[1])
			break
		}
	}

	return statusCode, stdout, nil
}

func getRange(url string, start int64, n int64) (io.ReadCloser, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error al crear la petición: %w", err)
	}
	rangeStr := fmt.Sprintf("bytes=%d-%d", start, start+n-1)
	req.Header.Set("Range", rangeStr)
	req.Header.Set("User-Agent", "curl/7.87.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error al realizar la petición: %w", err)
	}

	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("error: código de estado HTTP %d, se esperaba %d", resp.StatusCode, http.StatusPartialContent)
	}

	return resp.Body, nil
}

func fetchHeader(url string) ([]byte, uint64, error) {
	resp, _ := http.Head(url)
	r := resp.Header.Get("Accept-Ranges")
	if r != "bytes" {
		fmt.Printf("Accept-Ranges header ('%s') is not 'bytes'--trying anyway", r)
	}
	zipSize := resp.ContentLength
	start := max(zipSize-headerLen, 0)

	status, body, err := getRangeCurl(url, start, headerLen)

	if status != http.StatusPartialContent {
		err = fmt.Errorf("error: código de estado HTTP %d, se esperaba %d", status, http.StatusPartialContent)
	}
	if err != nil {
		return nil, 0, err
	}

	data, _ := io.ReadAll(body)
	return data, uint64(zipSize), nil
}

func infoIter(data []byte, zipSize uint64) ([]CDirentry, error) {
	magicEOCD64 := []byte{0x50, 0x4b, 0x06, 0x06}
	magicEOCD := []byte{0x50, 0x4b, 0x05, 0x06}

	var magic uint32
	var diskNum uint16
	var diskStart uint16
	var diskNumRecords uint16
	var totalNumRecords uint16
	var commentLen uint16

	var eocdSz uint64
	var createVer uint16
	var minVer uint16
	var diskNum32 uint32
	var diskStart32 uint32
	var diskNumRecords64 uint64
	var totalNumRecords64 uint64
	var cdirBytes64 uint64
	var cdirStart64 uint64

	i := bytes.LastIndex(data, magicEOCD64)
	if i >= 0 {
		reader := bytes.NewReader(data[i:])
		binary.Read(reader, binary.LittleEndian, &magic)
		binary.Read(reader, binary.LittleEndian, &eocdSz)
		binary.Read(reader, binary.LittleEndian, &createVer)
		binary.Read(reader, binary.LittleEndian, &minVer)
		binary.Read(reader, binary.LittleEndian, &diskNum32)
		binary.Read(reader, binary.LittleEndian, &diskStart32)
		binary.Read(reader, binary.LittleEndian, &diskNumRecords64)
		binary.Read(reader, binary.LittleEndian, &totalNumRecords64)
		binary.Read(reader, binary.LittleEndian, &cdirBytes64)
		binary.Read(reader, binary.LittleEndian, &cdirStart64)

	} else {
		i = bytes.LastIndex(data, magicEOCD)
		reader := bytes.NewReader(data[i:])

		var cdirStart uint32
		var cdirBytes uint32
		binary.Read(reader, binary.LittleEndian, &magic)
		binary.Read(reader, binary.LittleEndian, &diskNum)
		binary.Read(reader, binary.LittleEndian, &diskStart)
		binary.Read(reader, binary.LittleEndian, &diskNumRecords)
		binary.Read(reader, binary.LittleEndian, &totalNumRecords)
		binary.Read(reader, binary.LittleEndian, &cdirBytes)
		binary.Read(reader, binary.LittleEndian, &cdirStart)
		binary.Read(reader, binary.LittleEndian, &commentLen)
		cdirStart64 = uint64(cdirStart)
		cdirBytes64 = uint64(cdirBytes)
	}

	if cdirStart64 < 0 || cdirStart64 >= zipSize {
		return nil, fmt.Errorf("cannot find central directory")
	}

	var filehdrIndex uint64
	if zipSize <= headerLen {
		filehdrIndex = cdirStart64
	} else {
		filehdrIndex = headerLen - (zipSize - cdirStart64)
	}

	//TODO:
	//if filehdr_index < 0:
	//resp = self.get_range(cdir_start, self.zip_size - cdir_start)
	//filehdr_index = 0

	cdirEnd := filehdrIndex + cdirBytes64

	entries := make([]CDirentry, totalNumRecords)

	for i := 0; filehdrIndex < cdirEnd; i++ {
		var entry CDirentry
		filehdrIndex, entry, _ = unpackCDirentry(data, filehdrIndex)
		entries[i] = entry
	}
	return entries, nil
}

func unpackCDirentry(data []byte, offset uint64) (uint64, CDirentry, error) {
	reader := bytes.NewReader(data[offset:])
	var entry CDirentry
	currentOffset := offset

	var buffer32 uint32
	binary.Read(reader, binary.LittleEndian, &entry.Signature)
	binary.Read(reader, binary.LittleEndian, &entry.VersionMadeBy)
	binary.Read(reader, binary.LittleEndian, &entry.VersionNeeded)
	binary.Read(reader, binary.LittleEndian, &entry.GeneralPurposeBitFlag)
	binary.Read(reader, binary.LittleEndian, &entry.CompressionMethod)
	binary.Read(reader, binary.LittleEndian, &entry.LastModFileTime)
	binary.Read(reader, binary.LittleEndian, &entry.LastModFileDate)
	binary.Read(reader, binary.LittleEndian, &entry.Crc32)
	binary.Read(reader, binary.LittleEndian, &buffer32)
	entry.CompressedSize = uint64(buffer32)
	binary.Read(reader, binary.LittleEndian, &buffer32)
	entry.UncompressedSize = uint64(buffer32)
	binary.Read(reader, binary.LittleEndian, &entry.FileNameLength)
	binary.Read(reader, binary.LittleEndian, &entry.ExtraFieldLength)
	binary.Read(reader, binary.LittleEndian, &entry.FileCommentLength)
	binary.Read(reader, binary.LittleEndian, &entry.DiskNumberStart)
	binary.Read(reader, binary.LittleEndian, &entry.InternalFileAttributes)
	binary.Read(reader, binary.LittleEndian, &entry.ExternalFileAttributes)
	binary.Read(reader, binary.LittleEndian, &buffer32)
	entry.OffsetLocalHeader = uint64(buffer32)
	currentOffset += 46

	entry.FileName = string(data[int(currentOffset):int(currentOffset+uint64(entry.FileNameLength))])
	currentOffset += uint64(entry.FileNameLength)

	extra := data[int(currentOffset):int(currentOffset+uint64(entry.ExtraFieldLength))]
	currentOffset += uint64(entry.ExtraFieldLength)

	currentOffset += uint64(entry.FileCommentLength)

	i := 0
	for i < len(extra) {
		extraReader := bytes.NewReader(extra)
		var fieldid uint16
		var fieldsz uint16

		binary.Read(extraReader, binary.LittleEndian, &fieldid)
		binary.Read(extraReader, binary.LittleEndian, &fieldsz)

		i += 4

		if fieldid == 0x0001 { //ZIP64
			var vals []uint64

			if fieldsz == 8 {
				vals = make([]uint64, 1)
			} else if fieldsz == 16 {
				vals = make([]uint64, 2)
			} else {
				vals = make([]uint64, 3)
			}
			binary.Read(extraReader, binary.LittleEndian, &vals)

			if entry.UncompressedSize == 0xffffffff {
				entry.UncompressedSize = vals[0]
				vals = vals[1:]
			}

			if entry.CompressedSize == 0xffffffff {
				entry.CompressedSize = vals[0]
				vals = vals[1:]
			}

			if entry.OffsetLocalHeader == 0xffffffff {
				entry.OffsetLocalHeader = vals[0]
				vals = vals[1:]
			}
		}
		i += int(fieldsz)
	}
	//fmt.Printf("%s %x %x %x \n", fileName, entry.UncompressedSize, entry.CompressedSize, entry.OffsetLocalHeader)

	return currentOffset, entry, nil
}

func readLastNBytes(filePath string, n int64) ([]byte, uint64, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Get the file size
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("error getting file information: %w", err)
	}
	fileSize := fileInfo.Size()

	// Calculate the offset to read the last n bytes
	offset := fileSize - n
	if offset < 0 {
		offset = 0 // If n is greater than the file size, read from the beginning
		n = fileSize
	}

	// Create the buffer to read the last n bytes
	buffer := make([]byte, n)

	// Read the last n bytes from the calculated offset
	bytesRead, err := file.ReadAt(buffer, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading the last %d bytes: %w", n, err)
	}

	return buffer[:bytesRead], uint64(fileSize), nil
}

func readRange(filePath string, offset int64, n int64) ([]byte, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Create the buffer to read the last n bytes
	buffer := make([]byte, n)

	// Read the last n bytes from the calculated offset
	bytesRead, err := file.ReadAt(buffer, offset)
	if err != nil {
		return nil, fmt.Errorf("error reading the last %d bytes: %w", n, err)
	}

	return buffer[:bytesRead], nil
}

func main() {
	if len(os.Args) < 2 {
		println("uso: unzip_http URL [file_to_download]")
		return
	}

	url := os.Args[1]

	var toExtract string
	if len(os.Args) > 2 {
		toExtract = os.Args[2]
	} else {
		toExtract = ""
	}

	//data, fileLen, err := fetchHeader(url)
	//os.WriteFile("jsa.data", data, 0644)
	data, err := os.ReadFile("jsa.data")
	fileLen := uint64(2994802022)
	if err != nil {
		println(err.Error())
		return
	} else {
		fmt.Printf("fileLen: %d\n", fileLen)
	}

	entries, _ := infoIter(data, fileLen)

	for i, entry := range entries {
		fmt.Printf("%s %d %d %x \n", entry.FileName, entry.UncompressedSize, entry.CompressedSize, entry.OffsetLocalHeader)

		if entry.FileName == toExtract {
			sizeof_localhdr := int64(30)

			var nextPos uint64
			if len(entries) > i+1 {
				nextPos = entries[i+1].OffsetLocalHeader
			} else {
				nextPos = fileLen
			}

			fmt.Printf("Extracting: %s %d %d\n", toExtract, int64(entry.OffsetLocalHeader), nextPos)

			body, err1 := getRange(url, int64(entry.OffsetLocalHeader), int64(nextPos))
			status := 206
			if status != http.StatusPartialContent {
				err1 = fmt.Errorf("error: código de estado HTTP %d, se esperaba %d", status, http.StatusPartialContent)
			}
			if err1 != nil {
				print(err1.Error())
				return
			}
			_, err = io.CopyN(io.Discard, body, sizeof_localhdr-2)
			var extraLen uint16
			binary.Read(body, binary.LittleEndian, &extraLen)
			_, err = io.CopyN(io.Discard, body, int64(entry.FileNameLength)+int64(extraLen))

			data = make([]byte, entry.CompressedSize)
			bytesRead, err2 := io.ReadAtLeast(body, data, int(entry.CompressedSize))
			fmt.Printf("bytesRead: %d \n", bytesRead)
			//data, err2 := io.ReadAll(body)
			if err2 != nil {
				print(err2.Error())
				return
			}

			var decompressedData []byte
			var err error
			if entry.CompressionMethod == 8 {
				compressedData := bytes.NewBuffer(data)
				flateReader := flate.NewReader(compressedData)
				// Read all the decompressed data
				decompressedData, err = io.ReadAll(flateReader)
				if err != nil {
					println(err.Error())
				}
				flateReader.Close()
			} else {
				decompressedData = data
			}

			dir := filepath.Dir(entry.FileName)
			os.MkdirAll(dir, 0755)

			archivo, _ := os.Create(entry.FileName)
			archivo.Write(decompressedData)
			archivo.Close()
			fmt.Printf("done\n")
		}
	}
	return

}
