package keycloakb

import (
	"context"
	"database/sql"
)

const (
	updateConfigStmt = `INSERT INTO realm_configuration (realm_id, configuration) 
	  VALUES (?, ?) 
	  ON DUPLICATE KEY UPDATE configuration = ?;`
	selectConfigStmt = `SELECT configuration FROM realm_configuration WHERE (realm_id = ?)`
)

// DBConfiguration interface
type DBConfiguration interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	StoreOrUpdate(context.Context, string, string) error
	GetConfiguration(context.Context, string) (string, error)
}

type configurationDBModule struct {
	db DBConfiguration
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewConfigurationDBModule(db DBConfiguration) ConfigurationDBModule {
	return &configurationDBModule{
		db: db,
	}
}

func (c *configurationDBModule) StoreOrUpdate(context context.Context, realmID string, configJSON string) error {
	// update value in DB
	_, err := c.db.Exec(updateConfigStmt, realmID, configJSON, configJSON)
	return err
}

func (c *configurationDBModule) GetConfiguration(context context.Context, realmID string) (string, error) {
	var configJSON string
	row := c.db.QueryRow(selectConfigStmt, realmID)

	switch err := row.Scan(&configJSON); err {
	case sql.ErrNoRows:
		return configJSON, nil
	default:
		return configJSON, err
	}
}
