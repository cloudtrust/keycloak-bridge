package keycloakb

import (
	"database/sql"
	"time"
)

// NoopEventsDB is a eventsDB client that does nothing.
type NoopEventsDB struct{}

// Exec does nothing.
func (NoopEventsDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return NoopResult{}, nil
}

// Query does nothing.
func (NoopEventsDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return nil, nil
}

// QueryRow does nothing.
func (NoopEventsDB) QueryRow(query string, args ...interface{}) *sql.Row {
	return nil
}

func (NoopEventsDB) SetMaxOpenConns(n int) {

}
func (NoopEventsDB) SetMaxIdleConns(n int) {

}

func (NoopEventsDB) SetConnMaxLifetime(d time.Duration) {

}

// NoopResult is a sql.Result that does nothing.
type NoopResult struct{}

// LastInsertId does nothing.
func (NoopResult) LastInsertId() (int64, error) { return 0, nil }

// RowsAffected does nothing.
func (NoopResult) RowsAffected() (int64, error) { return 0, nil }
