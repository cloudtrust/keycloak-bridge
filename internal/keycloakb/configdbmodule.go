package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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

// RealmConfiguration struct
type RealmConfiguration struct {
	DefaultClientID                 *string `json:"default_client_id,omitempty"`
	DefaultRedirectURI              *string `json:"default_redirect_uri,omitempty"`
	APISelfAuthenticatorMgmtEnabled *bool   `json:"api_self_authenticator_mgmt_enabled"`
	APISelfPasswordChangeEnabled    *bool   `json:"api_self_password_change_enabled"`
	APISelfMailEditionEnabled       *bool   `json:"api_self_mail_edition_enabled"`
	APISelfDeleteAccountEnabled     *bool   `json:"api_self_delete_account_enabled"`
	UISelfAuthenticatorMgmtEnabled  *bool   `json:"ui_self_authenticator_mgmt_enabled"`
	UISelfPasswordChangeEnabled     *bool   `json:"ui_self_password_change_enabled"`
	UISelfMailEditionEnabled        *bool   `json:"ui_self_mail_edition_enabled"`
	UISelfDeleteAccountEnabled      *bool   `json:"ui_self_delete_account_enabled"`
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewConfigurationDBModule(db DBConfiguration) *configurationDBModule {
	return &configurationDBModule{
		db: db,
	}
}

func (c *configurationDBModule) StoreOrUpdate(context context.Context, realmID string, config RealmConfiguration) error {
	// transform customConfig object into JSON string
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateConfigStmt, realmID, string(configJSON), string(configJSON))
	return err
}

func (c *configurationDBModule) GetConfiguration(context context.Context, realmID string) (RealmConfiguration, error) {
	var configJSON string
	var config = RealmConfiguration{}
	row := c.db.QueryRow(selectConfigStmt, realmID)

	switch err := row.Scan(&configJSON); err {
	case sql.ErrNoRows:
		err = errors.New("RealmConfiguration is not configured for " + realmID)
		return RealmConfiguration{}, err
	default:
		if err != nil {
			return RealmConfiguration{}, err
		}

		err = json.Unmarshal([]byte(configJSON), &config)
		return config, err
	}
}
