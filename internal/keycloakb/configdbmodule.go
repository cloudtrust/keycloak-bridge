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

	selectAuthzStmt = `SELECT realm_id, group_id, action, target_realm_id, target_group_id FROM authorizations WHERE realm_id = ? AND group_id = ?;`
	deleteAuthzStmt = `DELETE FROM authorizations WHERE realm_id = ? AND group_id = ?;`
	createAuthzStmt = `INSERT INTO authorizations (realm_id, group_id, action, target_realm_id, target_group_id) 
		VALUES (?, ?, ?, ?, ?);`
	deleteAuthzWithGroupIDStmt = `DELETE FROM authorizations WHERE group_id = ? OR target_group_id = ?;`
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

func (c *configurationDBModule) GetAuthorizations(ctx context.Context, realmID string, groupID string) ([]dto.Authorization, error) {
	// Get Authorizations from DB
	rows, err := c.db.Query(selectAuthzStmt, realmID, groupID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorizations", "error", err.Error(), "realmID", realmID, "groupID", groupID)
		return nil, err
	}
	defer rows.Close()

	var authz dto.Authorization
	var res = make([]dto.Authorization, 0)
	for rows.Next() {
		authz, err = c.scanAuthorization(rows)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't get authorizations. Scan failed", "error", err.Error(), "realmID", realmID, "groupID", groupID)
			return nil, err
		}
		res = append(res, authz)
	}

	return res, nil
}

func (c *configurationDBModule) CreateAuthorization(context context.Context, auth dto.Authorization) error {
	_, err := c.db.Exec(createAuthzStmt, nullableString(auth.RealmID), nullableString(auth.GroupID),
		nullableString(auth.Action), nullableString(auth.TargetRealmID), nullableString(auth.TargetGroupID))
	return err
}

func (c *configurationDBModule) DeleteAuthorizations(context context.Context, realmID string, groupID string) error {
	_, err := c.db.Exec(deleteAuthzStmt, realmID, groupID)
	return err
}

func (c *configurationDBModule) DeleteAuthorizationsWithGroupID(context context.Context, groupID string) error {
	_, err := c.db.Exec(deleteAuthzWithGroupIDStmt, groupID, groupID)
	return err
}

func (c *configurationDBModule) NewTransaction(context context.Context) (database.Transaction, error) {
	return database.NewTransaction(c.db)
}

func (c *configurationDBModule) scanAuthorization(scanner Scanner) (dto.Authorization, error) {
	var (
		realmID       string
		groupID       string
		action        string
		targetGroupID string
		targetRealmID string
	)

	err := scanner.Scan(&realmID, &groupID, &action, &targetRealmID, &targetGroupID)
	if err != nil {
		return dto.Authorization{}, err
	}

	return dto.Authorization{
		RealmID:       &realmID,
		GroupID:       &groupID,
		Action:        &action,
		TargetRealmID: &targetRealmID,
		TargetGroupID: &targetGroupID,
	}, nil
}

func nullableString(value *string) interface{} {
	if value != nil {
		return value
	}
	return nil
}
