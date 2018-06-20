package health

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

const (
	createHealthTblStmt = `CREATE TABLE IF NOT EXISTS health (
		component_name STRING,
		component_id STRING,
		unit STRING,
		json JSONB,
		last_updated TIMESTAMPTZ,
		valid_until TIMESTAMPTZ,
		PRIMARY KEY (component_name, component_id, unit))`
	upsertHealthStmt = `UPSERT INTO health (
		component_name,
		component_id,
		unit,
		json,
		last_updated,
		valid_until)
		VALUES ($1, $2, $3, $4, $5, $6)`
	selectHealthStmt = `SELECT * FROM health WHERE (component_name = $1 AND component_id = $2 AND unit = $3)`
	cleanHealthStmt  = `DELETE from health WHERE (component_name = $1 AND valid_until < $2)`
)

type StoredReport struct {
	ComponentName   string
	ComponentID     string
	HealthcheckUnit string
	Reports         json.RawMessage
	LastUpdated     time.Time
	ValidUntil      time.Time
}

// StorageModule is the module that save health checks results in Storage DB.
type StorageModule struct {
	componentName string
	componentID   string
	db            Storage
}

type Storage interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// NewStorageModule returns the storage module.
func NewStorageModule(componentName, componentID string, db Storage) *StorageModule {
	// Init DB: create health table.
	db.Exec(createHealthTblStmt)

	return &StorageModule{
		componentName: componentName,
		componentID:   componentID,
		db:            db,
	}
}

// Update updates the health checks reports stored in DB with the values 'jsonReports'.
func (c *StorageModule) Update(unit string, validity time.Duration, jsonReports json.RawMessage) error {
	var now = time.Now()
	var _, err = c.db.Exec(upsertHealthStmt, c.componentName, c.componentID, unit, string(jsonReports), now.UTC(), now.Add(validity).UTC())

	if err != nil {
		return errors.Wrapf(err, "component '%s' with id '%s' could not update health check for unit '%s'", c.componentName, c.componentID, unit)
	}

	return nil
}

// Read reads the reports in DB.
func (c *StorageModule) Read(unit string) (StoredReport, error) {
	var rows, err = c.db.Query(selectHealthStmt, c.componentName, c.componentID, unit)
	if err != nil {
		return StoredReport{}, errors.Wrapf(err, "component '%s' with id '%s' could not read health check '%s'", c.componentName, c.componentID, unit)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cName, cID, hcUnit      string
			reports                 json.RawMessage
			lastUpdated, validUntil time.Time
		)

		var err = rows.Scan(&cName, &cID, &hcUnit, &reports, &lastUpdated, &validUntil)
		if err != nil {
			return StoredReport{}, errors.Wrapf(err, "component '%s' with id '%s' could not read health check '%s'", c.componentName, c.componentID, unit)
		}

		return StoredReport{
			ComponentName:   cName,
			ComponentID:     cID,
			HealthcheckUnit: hcUnit,
			Reports:         reports,
			LastUpdated:     lastUpdated.UTC(),
			ValidUntil:      validUntil.UTC(),
		}, nil

	}

	return StoredReport{}, nil
}

// Clean deletes the old test reports that are no longer valid from the health DB table.
func (c *StorageModule) Clean() error {
	var _, err = c.db.Exec(cleanHealthStmt, c.componentName, time.Now().UTC())

	if err != nil {
		return errors.Wrapf(err, "component '%s' with id '%s' could not clean health checks", c.componentName, c.componentID)
	}

	return nil
}
