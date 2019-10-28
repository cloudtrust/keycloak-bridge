package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"

	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
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

type configurationDBModule struct {
	db DBConfiguration
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewConfigurationDBModule(db DBConfiguration) *configurationDBModule {
	return &configurationDBModule{
		db: db,
	}
}

func (c *configurationDBModule) StoreOrUpdate(context context.Context, realmID string, config dto.RealmConfiguration) error {
	// transform customConfig object into JSON string
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateConfigStmt, realmID, string(configJSON), string(configJSON))
	return err
}

func (c *configurationDBModule) GetConfiguration(context context.Context, realmID string) (dto.RealmConfiguration, error) {
	var configJSON string
	var config = dto.RealmConfiguration{}
	row := c.db.QueryRow(selectConfigStmt, realmID)

	switch err := row.Scan(&configJSON); err {
	case sql.ErrNoRows:
		return dto.RealmConfiguration{}, errorhandler.Error{
			Status:  404,
			Message: MsgErrNotConfigured + "." + RealmConfiguration + "." + realmID,
		}

	default:
		if err != nil {
			return dto.RealmConfiguration{}, err
		}

		err = json.Unmarshal([]byte(configJSON), &config)
		return config, err
	}
}
