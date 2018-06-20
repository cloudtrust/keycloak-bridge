package keycloakb

import (
	"database/sql"
)

// NoopCockroach is a cockroach client that does nothing.
type NoopCockroach struct{}

// Exec does nothing.
func (NoopCockroach) Exec(query string, args ...interface{}) (sql.Result, error) {
	return NoopResult{}, nil
}

// Ping does nothing.
func (NoopCockroach) Ping() error { return nil }

// Query does nothing.
func (NoopCockroach) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, nil
}

// QueryRow does nothing.
func (NoopCockroach) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

// NoopResult is a sql.Result that does nothing.
type NoopResult struct{}

// LastInsertId does nothing.
func (NoopResult) LastInsertId() (int64, error) { return 0, nil }

// RowsAffected does nothing.
func (NoopResult) RowsAffected() (int64, error) { return 0, nil }
