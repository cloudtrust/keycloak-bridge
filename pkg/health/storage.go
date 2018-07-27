package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrInvalid  = errors.New("report not valid")
	ErrNotFound = errors.New("health check report not found")
)

type storedReport struct {
	ComponentName string
	ComponentID   string
	Module        string
	HealthCheck   string
	Report        json.RawMessage
	LastUpdated   time.Time
	ValidUntil    time.Time
}

// StorageModule is the module that save health checks results in Storage DB.
type StorageModule struct {
	componentName string
	componentID   string
	s             Storage
}

type Storage interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

const createHealthTblStmt = `
CREATE TABLE IF NOT EXISTS health (
	component_name STRING,
	component_id STRING,
	module STRING,
	healthcheck STRING,
	json JSONB,
	last_updated TIMESTAMPTZ,
	valid_until TIMESTAMPTZ,
PRIMARY KEY (component_name, component_id, module, healthcheck)
)`

// NewStorageModule returns the storage module.
func NewStorageModule(componentName, componentID string, s Storage) *StorageModule {
	// Init DB: create health table.
	s.Exec(createHealthTblStmt)

	return &StorageModule{
		componentName: componentName,
		componentID:   componentID,
		s:             s,
	}
}

const upsertHealthStmt = `
UPSERT INTO health (
	component_name,
	component_id,
	module,
	healthcheck,
	json, 
	last_updated,
	valid_until)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

// Update updates the health checks reports stored in DB with the values 'jsonReport'.
// jsonReport is an array of healthcheck reports for a given module, e.g. for jaeger:
// [
//   {
//     "name": "agent systemd unit",
//     "status": "OK",
//     "duration": "43.034µs"
//   },
//   {
//     "name": "ping collector",
//     "status": "OK",
//     "duration": "830.443µs"
//   }
// ]
//
func (sm *StorageModule) Update(ctx context.Context, module string, jsonReports json.RawMessage, validity time.Duration) error {
	var reports = []map[string]string{}
	json.Unmarshal(jsonReports, &reports)

	var now = time.Now()
	// Iterate over each healtcheck report
	for _, report := range reports {
		// Store each report as json
		var jsonReport []byte
		{
			var err error
			jsonReport, err = json.Marshal(report)
			if err != nil {
				return err
			}
		}

		var _, err = sm.s.Exec(upsertHealthStmt, sm.componentName, sm.componentID, module, report["name"], string(jsonReport), now.UTC(), now.Add(validity).UTC())

		if err != nil {
			return errors.Wrapf(err, "component '%s' with id '%s' could not update health check '%s' for module '%s'", sm.componentName, sm.componentID, report["name"], module)
		}
	}

	return nil
}

const selectOneHealthStmt = `
SELECT * FROM health
WHERE (component_name = $1 AND component_id = $2 AND module = $3 AND healthcheck = $4)`

const selectAllHealthStmt = `
SELECT * FROM health
WHERE (component_name = $1 AND component_id = $2 AND module = $3)`

// Read reads the reports in DB. Like the healthcheck modules, it returns the healthcheck report specified by the
// paramters 'module' and 'healtcheck' as an json encoded array, e.g. for jaeger:
// [
//   {
//     "name": "agent systemd unit",
//     "status": "OK",
//     "duration": "43.034µs"
//   },
//   {
//     "name": "ping collector",
//     "status": "OK",
//     "duration": "830.443µs"
//   }
// ]
// The parameter 'healthcheck' can be the empty string, in that case all reports for the given module are returned.
func (sm *StorageModule) Read(ctx context.Context, module, healthcheck string) (json.RawMessage, error) {
	var rows *sql.Rows
	{
		var err error
		if healthcheck == "" {
			rows, err = sm.s.Query(selectAllHealthStmt, sm.componentName, sm.componentID, module)
		} else {
			rows, err = sm.s.Query(selectOneHealthStmt, sm.componentName, sm.componentID, module, healthcheck)
		}

		if err != nil {
			return nil, errors.Wrapf(err, "component '%s' with id '%s' could not read health check '%s' for module %s", sm.componentName, sm.componentID, healthcheck, module)
		}
		// If there is no results, return an empty array
		if rows == nil {
			return nil, ErrNotFound
		}
	}
	defer rows.Close()

	var reports []json.RawMessage

	for rows.Next() {
		var (
			componentName, componentID, module, healthcheck string
			report                                          json.RawMessage
			lastUpdated, validUntil                         time.Time
		)

		var err = rows.Scan(&componentName, &componentID, &module, &healthcheck, &report, &lastUpdated, &validUntil)
		if err != nil {
			return nil, errors.Wrapf(err, "component '%s' with id '%s' could not read health check '%s' for module %s", sm.componentName, sm.componentID, healthcheck, module)
		}

		// If the health check was executed too long ago, the health check report
		// is considered not pertinant and an error is returned.
		if time.Now().After(validUntil) {
			return nil, ErrInvalid
		}

		reports = append(reports, report)
	}

	return json.MarshalIndent(reports, "", "  ")
}

const cleanHealthStmt = `
DELETE from health 
WHERE (component_name = $1 AND valid_until < $2)`

// Clean deletes the old test reports that are no longer valid from the health DB table.
func (sm *StorageModule) Clean() error {
	var _, err = sm.s.Exec(cleanHealthStmt, sm.componentName, time.Now().UTC())

	if err != nil {
		return errors.Wrapf(err, "component '%s' with id '%s' could not clean health checks", sm.componentName, sm.componentID)
	}

	return nil
}
