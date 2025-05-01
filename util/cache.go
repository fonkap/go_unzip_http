package util

import (
	"database/sql"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

// CacheEntry represents an entry in the cache table
type CacheEntry struct {
	URI      string
	ETag     string
	FileLen  int
	LastUsed time.Time
	Content  []byte
}

// Initializes SQLite database
func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cache (
        uri VARCHAR PRIMARY KEY,
        etag VARCHAR,
        file_len INT,
        last_used DATETIME,
        content BLOB
    )`)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Stores a CacheEntry in the database
func SaveToCache(db *sql.DB, entry CacheEntry) error {
	lastUsed := entry.LastUsed.Format("2006-01-02 15:04:05") // Convert time.Time to string

	_, err := db.Exec(`INSERT INTO cache (uri, etag, file_len, last_used, content) 
        VALUES (?, ?, ?, ?, ?) 
        ON CONFLICT(uri) DO UPDATE SET 
        etag = excluded.etag, 
        file_len = excluded.file_len, 
        last_used = excluded.last_used, 
        content = excluded.content`,
		entry.URI, entry.ETag, entry.FileLen, lastUsed, entry.Content)

	return err
}

// Retrieves a CacheEntry from SQLite
func LoadFromCache(db *sql.DB, uri string) (*CacheEntry, error) {
	var entry CacheEntry
	var lastUsedStr string

	err := db.QueryRow(`SELECT uri, etag, file_len, last_used, content FROM cache WHERE uri = ?`, uri).
		Scan(&entry.URI, &entry.ETag, &entry.FileLen, &lastUsedStr, &entry.Content)
	if err != nil {
		return nil, err
	}

	// Convert last_used string to time.Time
	entry.LastUsed, _ = time.Parse("2006-01-02 15:04:05", lastUsedStr)

	// Update last_used timestamp after access
	_, _ = db.Exec(`UPDATE cache SET last_used = ? WHERE uri = ?`, time.Now().Format("2006-01-02 15:04:05"), uri)

	return &entry, nil
}
