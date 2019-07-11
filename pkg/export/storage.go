package export

import (
	"database/sql"

	"github.com/pkg/errors"
)

const (
	upsertConfigStmt = `UPSERT INTO config (
		component_name,
		version,
		config)
		VALUES ($1, $2, $3)`
	selectConfigStmt = `SELECT * FROM config WHERE (component_name = $1 AND version = $2)`
)

// StorageModule is the module that saves configs in Storage DB.
type StorageModule struct {
	db DB
}

// DB interface
type DB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	QueryRow(query string, args ...interface{}) *sql.Row
}

// NewConfigStorageModule returns the storage module.
func NewConfigStorageModule(db DB) *StorageModule {
	return &StorageModule{
		db: db,
	}
}

// Save is used to save config in database
func (c *StorageModule) Save(componentName, version string, config []byte) error {
	var _, err = c.db.Exec(upsertConfigStmt, componentName, version, config)

	if err != nil {
		return errors.Wrapf(err, "cannotUpdateConfig.component'%s'WithVersion'%s'", componentName, version)
	}

	return nil
}

func (c *StorageModule) Read(componentName, version string) ([]byte, error) {
	var row = c.db.QueryRow(selectConfigStmt, componentName, version)
	var (
		cName, v string
		config   []byte
	)

	var err = row.Scan(&cName, &v, &config)
	if err != nil {
		return nil, errors.Wrapf(err, "cannotUpdateConfig.component'%s'WithVersion'%s'", componentName, version)
	}

	return config, nil
}
