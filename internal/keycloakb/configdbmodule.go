package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	updateConfigStmt = `INSERT INTO realm_configuration (realm_id, configuration)
	  VALUES (?, ?) 
	  ON DUPLICATE KEY UPDATE configuration = ?;`
	updateAdminConfigStmt = `INSERT INTO realm_configuration (realm_id, admin_configuration)
	  VALUES (?, ?)
	  ON DUPLICATE KEY UPDATE admin_configuration = ?;`
	selectBOConfigStmt = `
		SELECT distinct target_realm_id, target_type, target_group_name
		FROM backoffice_configuration
		WHERE realm_id=? AND group_name IN (???)
	`
	insertBOConfigStmt = `
		INSERT INTO backoffice_configuration (realm_id, group_name, target_realm_id, target_type, target_group_name)
		VALUES (?,?,?,?,?)
	`
	deleteBOConfigStmt = `
		DELETE FROM backoffice_configuration
		WHERE realm_id=?
		  AND group_name=?
		  AND target_realm_id=?
		  AND (? IS NULL OR target_type=?)
		  AND (? IS NULL OR target_group_name=?)
	`
	selectAuthzStmt       = `SELECT realm_id, group_name, action, target_realm_id, target_group_name FROM authorizations WHERE realm_id = ? AND group_name = ?;`
	selectSingleAuthzStmt = `
		SELECT
			realm_id, group_name, action, target_realm_id, target_group_name
		FROM authorizations 
		WHERE realm_id = ? 
		  AND group_name = ? 
		  AND action = ? 
		  AND target_realm_id = ? 
		  AND target_group_name = ?;
	`
	selectAuthzActionStmt = `
		SELECT
			realm_id, group_name, action, target_realm_id, target_group_name
		FROM authorizations 
		WHERE realm_id = ? 
		  AND group_name = ? 
		  AND action = ?;
	`
	createAuthzStmt = `INSERT INTO authorizations (realm_id, group_name, action, target_realm_id, target_group_name) 
		VALUES (?, ?, ?, ?, ?);`
	deleteAuthzStmt             = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ?;`
	deleteAllAuthzWithGroupStmt = `DELETE FROM authorizations WHERE (realm_id = ? AND group_name = ?) OR (target_realm_id = ? AND target_group_name = ?);`
	deleteSingleAuthzStmt       = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ? AND target_realm_id = ? AND target_group_name = ?;`
	deleteSingleGlobalAuthzStmt = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ? AND target_realm_id = ? AND target_group_name is NULL;`
)

// Scanner used to get data from SQL cursors
type Scanner interface {
	Scan(...interface{}) error
}

type configurationDBModule struct {
	configuration.ConfigurationReaderDBModule
	db     sqltypes.CloudtrustDB
	logger log.Logger
}

// NewConfigurationDBModule returns a ConfigurationDB module.
func NewConfigurationDBModule(db sqltypes.CloudtrustDB, logger log.Logger, actions ...[]string) ConfigurationDBModule {
	return &configurationDBModule{
		ConfigurationReaderDBModule: *configuration.NewConfigurationReaderDBModule(db, logger, actions...),
		db:                          db,
		logger:                      logger,
	}
}

func (c *configurationDBModule) GetConfigurations(ctx context.Context, realmID string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error) {
	config, adminConfig, err := c.ConfigurationReaderDBModule.GetRealmConfigurations(ctx, realmID)

	if err == sql.ErrNoRows {
		return config, adminConfig, errorhandler.Error{
			Status:  404,
			Message: ComponentName + "." + msg.MsgErrNotConfigured + "." + msg.RealmConfiguration + "." + realmID,
		}
	}
	return config, adminConfig, err
}

func (c *configurationDBModule) StoreOrUpdateConfiguration(context context.Context, realmID string, config configuration.RealmConfiguration) error {
	// transform customConfig object into JSON string
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// update value in DB
	_, err = c.db.Exec(updateConfigStmt, realmID, string(configJSON), string(configJSON))
	return err
}

func (c *configurationDBModule) GetConfiguration(ctx context.Context, realmID string) (configuration.RealmConfiguration, error) {
	config, err := c.ConfigurationReaderDBModule.GetConfiguration(ctx, realmID)

	if err == sql.ErrNoRows {
		return config, errorhandler.Error{
			Status:  404,
			Message: ComponentName + "." + msg.MsgErrNotConfigured + "." + msg.RealmConfiguration + "." + realmID,
		}
	}
	return config, err
}

func (c *configurationDBModule) StoreOrUpdateAdminConfiguration(context context.Context, realmID string, config configuration.RealmAdminConfiguration) error {
	var bytes, _ = json.Marshal(config)
	var configJSON = string(bytes)
	// update value in DB
	var _, err = c.db.Exec(updateAdminConfigStmt, realmID, configJSON, configJSON)
	return err
}

func (c *configurationDBModule) GetAdminConfiguration(ctx context.Context, realmID string) (configuration.RealmAdminConfiguration, error) {
	return c.ConfigurationReaderDBModule.GetAdminConfiguration(ctx, realmID)
}

func (c *configurationDBModule) GetBackOfficeConfiguration(ctx context.Context, realmID string, groupNames []string) (dto.BackOfficeConfiguration, error) {
	var sqlRequest = strings.Replace(selectBOConfigStmt, "???", "?"+strings.Repeat(",?", len(groupNames)-1), 1)
	var args = []interface{}{realmID}
	for _, grp := range groupNames {
		args = append(args, grp)
	}

	var rows, err = c.db.Query(sqlRequest, args...)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get back-office configuration", "err", err.Error(), "realmID", realmID, "groups", strings.Join(groupNames, ","))
		return nil, err
	}
	defer rows.Close()

	var res = make(dto.BackOfficeConfiguration)
	for rows.Next() {
		var targetRealmID, targetType, targetGroupName string
		err = rows.Scan(&targetRealmID, &targetType, &targetGroupName)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't get row from back-office configuration", "err", err.Error(), "realmID", realmID, "groups", strings.Join(groupNames, ","))
			return nil, err
		}
		if _, ok := res[targetRealmID]; !ok {
			res[targetRealmID] = make(map[string][]string)
		}
		if realmSubConf, ok := res[targetRealmID][targetType]; !ok {
			res[targetRealmID][targetType] = []string{targetGroupName}
		} else {
			res[targetRealmID][targetType] = append(realmSubConf, targetGroupName)
		}
	}

	return res, nil
}

func (c *configurationDBModule) DeleteBackOfficeConfiguration(ctx context.Context, realmID, groupName, targetRealmID string, targetType *string, targetGroupName *string) error {
	var _, err = c.db.Exec(deleteBOConfigStmt, realmID, groupName, targetRealmID, targetType, targetType, targetGroupName, targetGroupName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete back-office configuration", "err", err.Error(), "realmName", realmID, "group", groupName,
			"targetRealmName", targetRealmID, "targetType", targetType, "group", targetGroupName)
		return err
	}
	return nil
}

func (c *configurationDBModule) InsertBackOfficeConfiguration(ctx context.Context, realmID, groupName, targetRealmID, targetType string, targetGroupNames []string) error {
	for _, targetGroupName := range targetGroupNames {
		var _, err = c.db.Exec(insertBOConfigStmt, realmID, groupName, targetRealmID, targetType, targetGroupName)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't insert into back-office configuration", "err", err.Error(), "realmID", realmID, "groupName", groupName,
				"targetRealmName", targetRealmID, "targetType", targetType, "group", targetGroupName)
			return err
		}
	}
	return nil
}

func (c *configurationDBModule) GetAuthorizations(ctx context.Context, realmID string, groupName string) ([]configuration.Authorization, error) {
	// Get Authorizations from DB
	rows, err := c.db.Query(selectAuthzStmt, realmID, groupName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorizations", "err", err.Error(), "realmID", realmID, "groupName", groupName)
		return nil, err
	}
	defer rows.Close()

	var authz configuration.Authorization
	var res = make([]configuration.Authorization, 0)
	for rows.Next() {
		authz, err = c.scanAuthorization(rows)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't get authorizations. Scan failed", "err", err.Error(), "realmID", realmID, "groupName", groupName)
			return nil, err
		}
		res = append(res, authz)
	}

	return res, nil
}

func (c *configurationDBModule) GetAuthorization(ctx context.Context, realmID string, groupName string, targetRealm string, targetGroupName string, actionReq string) (configuration.Authorization, error) {
	// Get Authorization from DB
	row := c.db.QueryRow(selectSingleAuthzStmt, realmID, groupName, actionReq, targetRealm, targetGroupName)

	authz, err := c.scanAuthorization(row)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorization. Scan failed", "err", err.Error(), "realmID", realmID, "groupName", groupName, "targetRealm", targetRealm, "targetGroupName", targetGroupName, "action", actionReq)
		return configuration.Authorization{}, err
	}

	return authz, nil
}

func (c *configurationDBModule) GetAuthorizationsForAction(context context.Context, realmID string, groupName string, actionReq string) ([]configuration.Authorization, error) {
	// Get Authorizations from DB
	rows, err := c.db.Query(selectAuthzActionStmt, realmID, groupName, actionReq)
	if err != nil {
		c.logger.Warn(context, "msg", "Can't get authorizations", "err", err.Error(), "realmID", realmID, "groupName", groupName, "action", actionReq)
		return nil, err
	}
	defer rows.Close()

	var authz configuration.Authorization
	var res = make([]configuration.Authorization, 0)
	for rows.Next() {
		authz, err = c.scanAuthorization(rows)
		if err != nil {
			c.logger.Warn(context, "msg", "Can't get authorizations. Scan failed", "err", err.Error(), "realmID", realmID, "groupName", groupName, "action", actionReq)
			return nil, err
		}
		res = append(res, authz)
	}

	return res, nil
}

func (c *configurationDBModule) CreateAuthorization(context context.Context, auth configuration.Authorization) error {
	_, err := c.db.Exec(createAuthzStmt, nullableString(auth.RealmID), nullableString(auth.GroupName),
		nullableString(auth.Action), nullableString(auth.TargetRealmID), nullableString(auth.TargetGroupName))
	return err
}

func (c *configurationDBModule) DeleteAuthorizations(context context.Context, realmID string, groupName string) error {
	_, err := c.db.Exec(deleteAuthzStmt, realmID, groupName)
	return err
}

func (c *configurationDBModule) DeleteAuthorization(context context.Context, realmID string, groupName string, targetRealm string, targetGroupName string, actionReq string) error {
	var err error
	if targetGroupName == "" {
		_, err = c.db.Exec(deleteSingleGlobalAuthzStmt, realmID, groupName, actionReq, targetRealm)
	} else {
		_, err = c.db.Exec(deleteSingleAuthzStmt, realmID, groupName, actionReq, targetRealm, targetGroupName)
	}

	return err
}

func (c *configurationDBModule) DeleteAllAuthorizationsWithGroup(context context.Context, realmID, groupName string) error {
	_, err := c.db.Exec(deleteAllAuthzWithGroupStmt, realmID, groupName, realmID, groupName)
	return err
}

func (c *configurationDBModule) NewTransaction(context context.Context) (sqltypes.Transaction, error) {
	return c.db.BeginTx(context, nil)
}

func (c *configurationDBModule) scanAuthorization(scanner Scanner) (configuration.Authorization, error) {
	var (
		realmID         string
		groupName       string
		action          string
		targetRealmID   sql.NullString
		targetGroupName sql.NullString
	)

	err := scanner.Scan(&realmID, &groupName, &action, &targetRealmID, &targetGroupName)
	if err != nil {
		return configuration.Authorization{}, err
	}

	var authz = configuration.Authorization{
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
