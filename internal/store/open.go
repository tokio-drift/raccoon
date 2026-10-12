// Package store persists streams, events, files and verdicts in SQLite.
package store

import (
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion is the value of PRAGMA user_version written by Open.
const schemaVersion = 1

// ErrNewerVersion is returned when a database was created by a newer RACCOON.
var ErrNewerVersion = errors.New("store: database schema is newer than supported")

// ErrClosed is returned when a write happens after Close.
var ErrClosed = errors.New("store: database is closed")

// DB is a case database. All writes go through a single writer goroutine that
// commits transactions of at least insertBatch rows; reads may use *sql.DB
// directly through Conn.
type DB struct {
	conn *sql.DB

	ch      chan *req
	flushed chan struct{}
	mu      sync.Mutex
	closed  bool
}

// Conn exposes the underlying database for read queries (see Phase 4.4).
func (db *DB) Conn() *sql.DB { return db.conn }

// Open opens (or creates) the database at path, applying the schema exactly
// when user_version is 0 and refusing databases from a newer version.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, err
	}
	var uv int
	if err := conn.QueryRow("PRAGMA user_version").Scan(&uv); err != nil {
		conn.Close()
		return nil, fmt.Errorf("store: read schema version: %w", err)
	}
	switch {
	case uv == 0:
		if err := applySchema(conn); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := conn.Exec("PRAGMA user_version = 1"); err != nil {
			conn.Close()
			return nil, err
		}
	case uv == schemaVersion:
		// Reuse the existing database.
	default:
		conn.Close()
		return nil, fmt.Errorf("%w: user_version=%d, supported=%d", ErrNewerVersion, uv, schemaVersion)
	}

	db := &DB{
		conn:    conn,
		ch:      make(chan *req, 64),
		flushed: make(chan struct{}),
	}
	go db.loop()
	return db, nil
}

func applySchema(conn *sql.DB) error {
	for _, stmt := range splitStatements(schemaSQL) {
		if _, err := conn.Exec(stmt); err != nil {
			return fmt.Errorf("store: apply schema: %w", err)
		}
	}
	return nil
}

// splitStatements splits an embedded SQL script into single statements.
func splitStatements(s string) []string {
	var out []string
	for _, stmt := range strings.Split(s, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

// Close flushes pending writes and closes the database. It must be called after
// all producers have finished inserting.
func (db *DB) Close() error {
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil
	}
	db.closed = true
	close(db.ch)
	db.mu.Unlock()
	<-db.flushed
	return db.conn.Close()
}
