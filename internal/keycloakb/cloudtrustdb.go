package keycloakb

import (
	"database/sql"
	"time"
)

// NoopDB is a database client that does nothing.
type NoopDB struct{}

// Exec does nothing.
func (NoopDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return NoopResult{}, nil
}

// Query does nothing.
func (NoopDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, nil
}

// QueryRow does nothing.
func (NoopDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

func (NoopDB) SetMaxOpenConns(n int) {

}
func (NoopDB) SetMaxIdleConns(n int) {

}

func (NoopDB) SetConnMaxLifetime(d time.Duration) {

}

// NoopResult is a sql.Result that does nothing.
type NoopResult struct{}

// LastInsertId does nothing.
func (NoopResult) LastInsertId() (int64, error) { return 0, nil }

// RowsAffected does nothing.
func (NoopResult) RowsAffected() (int64, error) { return 0, nil }
