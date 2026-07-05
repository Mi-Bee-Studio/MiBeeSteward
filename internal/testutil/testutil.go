// Package testutil provides helpers for setting up in-memory SQLite databases in tests.
//
// Usage:
//
//	db, err := testutil.SetupTestDBFromSchema()
//	if err != nil {
//	    t.Fatal(err)
//	}
//	t.Cleanup(func() { db.Close() })
package testutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // register the pure-Go SQLite driver for database/sql
)

// SetupTestDB creates an in-memory SQLite database and executes the given schema.
// The caller is responsible for closing the returned *sql.DB.
func SetupTestDB(schemaContent string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}

	// Enable WAL mode for test performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}

	// Set busy timeout to prevent lock contention
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, err
	}

	if _, err := db.Exec(schemaContent); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// ReadSchemaFile reads db/schema.sql from the project root directory.
// It uses runtime.Caller to locate the source file and derives the project root
// by traversing up from internal/testutil/.
func ReadSchemaFile() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		// Fallback: try relative path from working directory
		data, err := os.ReadFile("db/schema.sql")
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	// filename is /abs/path/to/project/internal/testutil/testutil.go
	// Project root is 3 directories up from the file's directory
	dir := filepath.Dir(filename) // internal/testutil
	dir = filepath.Dir(dir)       // internal
	dir = filepath.Dir(dir)       // project root

	schemaPath := filepath.Join(dir, "db", "schema.sql")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// SetupTestDBFromSchema reads db/schema.sql and creates an in-memory SQLite
// database with all tables set up. The caller is responsible for closing the
// returned *sql.DB.
func SetupTestDBFromSchema() (*sql.DB, error) {
	schema, err := ReadSchemaFile()
	if err != nil {
		return nil, err
	}

	return SetupTestDB(schema)
}
