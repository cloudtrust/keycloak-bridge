package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
)

const (
	updateConfigStmt = `INSERT INTO realm_configuration (realm_id, configuration) 
	  VALUES (?, ?) 
	  ON DUPLICATE KEY UPDATE configuration = ?;`
	selectConfigStmt = `SELECT configuration FROM realm_configuration WHERE (realm_id = ?)`
	selectAuthzStmt  = `SELECT realm_id, group_name, action, target_realm_id, target_group_name FROM authorizations WHERE realm_id = ? AND group_name = ?;`
	createAuthzStmt  = `INSERT INTO authorizations (realm_id, group_name, action, target_realm_id, target_group_name) 
		VALUES (?, ?, ?, ?, ?);`
	deleteAuthzStmt             = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ?;`
	deleteAllAuthzWithGroupStmt = `DELETE FROM authorizations WHERE (realm_id = ? AND group_name = ?) OR (target_realm_id = ? AND target_group_name = ?);`
)

// Scanner used to get data from SQL cursors
type Scanner interface {
	Scan(...interface{}) error
}

type configurationDBModule struct {
	db     sqltypes.CloudtrustDB
	logger log.Logger
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewConfigurationDBModule(db sqltypes.CloudtrustDB, logger log.Logger) ConfigurationDBModule {
	return &configurationDBModule{
		db:     db,
		logger: logger,
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
		return config, errorhandler.Error{
			Status:  404,
			Message: ComponentName + "." + msg.MsgErrNotConfigured + "." + msg.RealmConfiguration + "." + realmID,
		}

	default:
		if err != nil {
			return config, err
		}

		err = json.Unmarshal([]byte(configJSON), &config)
		return config, err
	}
}

func (c *configurationDBModule) GetAuthorizations(ctx context.Context, realmID string, groupName string) ([]dto.Authorization, error) {
	// Get Authorizations from DB
	rows, err := c.db.Query(selectAuthzStmt, realmID, groupName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorizations", "error", err.Error(), "realmID", realmID, "groupName", groupName)
		return nil, err
	}
	defer rows.Close()

	var authz dto.Authorization
	var res = make([]dto.Authorization, 0)
	for rows.Next() {
		authz, err = c.scanAuthorization(rows)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't get authorizations. Scan failed", "error", err.Error(), "realmID", realmID, "groupName", groupName)
			return nil, err
		}
		res = append(res, authz)
	}

	return res, nil
}

func (c *configurationDBModule) CreateAuthorization(context context.Context, auth dto.Authorization) error {
	_, err := c.db.Exec(createAuthzStmt, nullableString(auth.RealmID), nullableString(auth.GroupName),
		nullableString(auth.Action), nullableString(auth.TargetRealmID), nullableString(auth.TargetGroupName))
	return err
}

func (c *configurationDBModule) DeleteAuthorizations(context context.Context, realmID string, groupName string) error {
	_, err := c.db.Exec(deleteAuthzStmt, realmID, groupName)
	return err
}

func (c *configurationDBModule) DeleteAllAuthorizationsWithGroup(context context.Context, realmID, groupName string) error {
	_, err := c.db.Exec(deleteAllAuthzWithGroupStmt, realmID, groupName, realmID, groupName)
	return err
}

func (c *configurationDBModule) NewTransaction(context context.Context) (database.Transaction, error) {
	return database.NewTransaction(c.db)
}

func (c *configurationDBModule) scanAuthorization(scanner Scanner) (dto.Authorization, error) {
	var (
		realmID         string
		groupName       string
		action          string
		targetRealmID   sql.NullString
		targetGroupName sql.NullString
	)

	err := scanner.Scan(&realmID, &groupName, &action, &targetRealmID, &targetGroupName)
	if err != nil {
		return dto.Authorization{}, err
	}

	var authz = dto.Authorization{
		RealmID:   &realmID,
		GroupName: &groupName,
		Action:    &action,
	}

	if targetRealmID.Valid {
		authz.TargetRealmID = &targetRealmID.String
	}

	if targetGroupName.Valid {
		authz.TargetGroupName = &targetGroupName.String
	}

	return authz, nil
}

func nullableString(value *string) interface{} {
	if value != nil {
		return value
	}
	return nil
}
