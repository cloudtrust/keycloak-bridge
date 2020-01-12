package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"

	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	selectAuthzStmt = `SELECT configuration FROM authorization_configuration WHERE realm_id = ? AND group_name = ?;`
	createAuthzStmt = `INSERT INTO authorization_configuration (realm_id, group_name, configuration) 
	VALUES (?, ?, ?);`
	updateAuthzStmt = `UPDATE authorization_configuration SET configuration = ? WHERE realm_id = ? AND group_name = ?;`
	deleteAuthzStmt = `DELETE FROM authorization_configuration WHERE realm_id = ? AND group_name = ?;`
)

// AuthorizationDBModule is the interface of the authorization DB module.
type AuthorizationDBModule interface {
	GetAuthorization(context context.Context, realmID string, groupName string) (dto.AuthorizationConfiguration, error)
	CreateAuthorization(context context.Context, realmID string, groupName string) error
	UpdateAuthorization(context context.Context, realmID string, groupName string, config dto.AuthorizationConfiguration) error
	DeleteAuthorization(context context.Context, realmID string, groupName string) error
}

type authzDBModule struct {
	db DBConfiguration
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewAuthzDBModule(db DBConfiguration) AuthorizationDBModule {
	return &authzDBModule{
		db: db,
	}
}

func (c *authzDBModule) GetAuthorization(context context.Context, realmID string, groupName string) (dto.AuthorizationConfiguration, error) {
	var configJSON string
	var config = dto.AuthorizationConfiguration{}
	row := c.db.QueryRow(selectAuthzStmt, realmID, groupName)

	switch err := row.Scan(&configJSON); err {
	case sql.ErrNoRows:
		return config, errorhandler.Error{
			Status:  404,
			Message: ComponentName + "." + MsgErrNotConfigured + "." + AuthorizationConfiguation + "." + realmID + "." + groupName,
		}

	default:
		if err != nil {
			return config, err
		}

		err = json.Unmarshal([]byte(configJSON), &config)
		return config, err
	}
}

func (c *authzDBModule) CreateAuthorization(context context.Context, realmID string, groupName string) error {
	// Create entry value in DB
	_, err := c.db.Exec(createAuthzStmt, realmID, groupName, "{}")
	return err
}

func (c *authzDBModule) UpdateAuthorization(context context.Context, realmID string, groupName string, config dto.AuthorizationConfiguration) error {
	// transform customConfig object into JSON string
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// Update entry value in DB
	_, err = c.db.Exec(updateAuthzStmt, realmID, groupName, configJSON)
	return err
}

func (c *authzDBModule) DeleteAuthorization(context context.Context, realmID string, groupName string) error {
	// Create entry value in DB
	_, err := c.db.Exec(deleteAuthzStmt, realmID, groupName)
	return err
}
