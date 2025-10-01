package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
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
	selectAllContextKeyID = `select id from context_key_configuration`
	deleteContextKeyStmt  = `DELETE from context_key_configuration WHERE id = ? and customer_realm = ifnull(?, customer_realm)`
	storeContextKeyStmt   = `
		INSERT INTO context_key_configuration (id, label, identities_realm, customer_realm, configuration)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE label=VALUES(label), identities_realm=VALUES(identities_realm), configuration=VALUES(configuration)
	`
	selectAuthzStmt       = `SELECT realm_id, group_name, action, target_realm_id, target_group_name FROM authorizations WHERE realm_id = ? AND group_name = ?;`
	selectSingleAuthzStmt = `
		SELECT
			1
		FROM authorizations 
		WHERE realm_id = ? 
		  AND group_name = ? 
		  AND action = ? 
		  AND target_realm_id = ? 
		  AND target_group_name = ?;
	`
	selectSingleGlobalAuthzStmt = `
		SELECT
			1
		FROM authorizations 
		WHERE realm_id = ? 
		  AND group_name = ? 
		  AND action = ? 
		  AND target_realm_id = ? 
		  AND target_group_name IS NULL;
	`
	createAuthzStmt = `INSERT INTO authorizations (realm_id, group_name, action, target_realm_id, target_group_name) 
		VALUES (?, ?, ?, ?, ?);`
	deleteAllAuthzWithGroupStmt = `DELETE FROM authorizations WHERE (realm_id = ? AND group_name = ?) OR (target_realm_id = ? AND target_group_name = ?);`
	deleteSingleAuthzStmt       = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ? AND target_realm_id = ? AND target_group_name = ?;`
	deleteGlobalAuthzStmt       = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ? AND target_realm_id = ? AND target_group_name IS NULL;`
	deleteAuthzEveryRealmsStmt  = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ?;`
	deleteAuthzRealmStmt        = `DELETE FROM authorizations WHERE realm_id = ? AND group_name = ? AND action = ? AND target_realm_id = ?;`

	selectThemeConfigStmt = `SELECT settings, logo, favicon FROM theme_configuration WHERE realm_name = ?;`
	updateThemeConfigStmt = `
		INSERT INTO theme_configuration (realm_name, settings, logo, favicon, translations)
		VALUES (?,?,?,?,?)
		ON DUPLICATE KEY UPDATE
			settings = VALUES(settings),
			logo = VALUES(logo),
			favicon = VALUES(favicon),
			translations = VALUES(translations);
	`
	selectTranslationStmt = `SELECT json_extract(translations, '$.???') FROM theme_configuration WHERE realm_name = ?;`
)

// executableSQL interface is used as a common descriptor for both DBModule and Transaction
type executableSQL interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type dbExecutable func(query string, args ...any) error

func deleteAuthorization(executable dbExecutable, realmID string, groupName string, targetRealm string, targetGroupName *string, actionReq string) error {
	var err error
	if targetGroupName != nil {
		err = executable(deleteSingleAuthzStmt, realmID, groupName, actionReq, targetRealm, targetGroupName)
	} else {
		err = executable(deleteGlobalAuthzStmt, realmID, groupName, actionReq, targetRealm)
	}

	return err
}

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

func (c *configurationDBModule) chooseExecutableSQL(tx sqltypes.Transaction) executableSQL {
	if tx != nil {
		return tx
	}
	return c.db
}

func (c *configurationDBModule) execNoResult(query string, args ...any) error {
	_, err := c.db.Exec(query, args...)
	return err
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
	return c.execNoResult(updateConfigStmt, realmID, string(configJSON), string(configJSON))
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
	return c.execNoResult(updateAdminConfigStmt, realmID, configJSON, configJSON)
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
	if err = rows.Err(); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get row from back-office configuration", "err", err.Error(), "realmID", realmID, "groups", strings.Join(groupNames, ","))
		return nil, err
	}

	return res, nil
}

func (c *configurationDBModule) DeleteBackOfficeConfiguration(ctx context.Context, realmID, groupName, targetRealmID string, targetType *string, targetGroupName *string) error {
	if err := c.execNoResult(deleteBOConfigStmt, realmID, groupName, targetRealmID, targetType, targetType, targetGroupName, targetGroupName); err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete back-office configuration", "err", err.Error(), "realmName", realmID, "group", groupName,
			"targetRealmName", targetRealmID, "targetType", targetType, "group", targetGroupName)
		return err
	}
	return nil
}

func (c *configurationDBModule) InsertBackOfficeConfiguration(ctx context.Context, realmID, groupName, targetRealmID, targetType string, targetGroupNames []string) error {
	for _, targetGroupName := range targetGroupNames {
		if err := c.execNoResult(insertBOConfigStmt, realmID, groupName, targetRealmID, targetType, targetGroupName); err != nil {
			c.logger.Warn(ctx, "msg", "Can't insert into back-office configuration", "err", err.Error(), "realmID", realmID, "groupName", groupName,
				"targetRealmName", targetRealmID, "targetType", targetType, "group", targetGroupName)
			return err
		}
	}
	return nil
}

func (c *configurationDBModule) GetAllContextKeyID(ctx context.Context) ([]string, error) {
	rows, err := c.db.Query(selectAllContextKeyID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get all context key ids", "err", err.Error())
		return nil, err
	}
	defer rows.Close()

	var res []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			c.logger.Warn(ctx, "msg", "Can't get all context key ids. Scan failed", "err", err.Error())
			return nil, err
		}
		res = append(res, id)
	}
	if err = rows.Err(); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get all context key ids. Failed to iterate on every items", "err", err.Error())
		return nil, err
	}

	return res, nil
}

// GetContextKeysForCustomerRealm gets all the context keys configuration for a given customer realm
func (c *configurationDBModule) GetContextKeysForCustomerRealm(ctx context.Context, customerRealm string) ([]configuration.RealmContextKey, error) {
	return c.ConfigurationReaderDBModule.GetContextKeysForCustomerRealm(ctx, customerRealm)
}

// GetDefaultContextKeyConfiguration gets the default context key configuration for a given customer realm
func (c *configurationDBModule) GetDefaultContextKeyConfiguration(ctx context.Context, customerRealm string) (configuration.RealmContextKey, error) {
	return c.ConfigurationReaderDBModule.GetDefaultContextKeyForCustomerRealm(ctx, customerRealm)
}

// DeleteContextKeyConfiguration deletes the specified context key configuration for a given customer realm
func (c *configurationDBModule) DeleteContextKeyConfiguration(ctx context.Context, tx sqltypes.Transaction, customerRealm string, ID string) error {
	_, err := c.chooseExecutableSQL(tx).Exec(deleteContextKeyStmt, ID, customerRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete a context key configuration", "realm", customerRealm, "id", ID, "err", err.Error())
		return err
	}
	return nil
}

// StoreContextKeyConfiguration sets a context key configuration for a given customer realm
func (c *configurationDBModule) StoreContextKeyConfiguration(ctx context.Context, tx sqltypes.Transaction, contextKey configuration.RealmContextKey) error {
	configJSON, err := json.Marshal(contextKey.Config)
	if err != nil {
		c.logger.Warn(ctx, "msg", "JSON marshaling failed")
		return err
	}

	_, err = c.chooseExecutableSQL(tx).Exec(storeContextKeyStmt, contextKey.ID, contextKey.Label, contextKey.IdentitiesRealm, contextKey.CustomerRealm, configJSON)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't set context key in db", "realm", contextKey.CustomerRealm, "id", contextKey.ID, "err", err.Error())
		return err
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
	if err = rows.Err(); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get authorizations. Failed to iterate on every items.", "err", err.Error(), "realmID", realmID, "groupName", groupName)
		return nil, err
	}

	return res, nil
}

func (c *configurationDBModule) AuthorizationExists(ctx context.Context, realmID string, groupName string, targetRealm string, targetGroupName *string, actionReq string) (bool, error) {
	var row sqltypes.SQLRow
	// Get Authorization from DB
	if targetGroupName != nil {
		row = c.db.QueryRow(selectSingleAuthzStmt, realmID, groupName, actionReq, targetRealm, targetGroupName)
	} else {
		row = c.db.QueryRow(selectSingleGlobalAuthzStmt, realmID, groupName, actionReq, targetRealm)
	}

	var exists int
	err := row.Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func (c *configurationDBModule) CreateAuthorization(context context.Context, auth configuration.Authorization) error {
	return c.execNoResult(createAuthzStmt, nullableString(auth.RealmID), nullableString(auth.GroupName),
		nullableString(auth.Action), nullableString(auth.TargetRealmID), nullableString(auth.TargetGroupName))
}

func (c *configurationDBModule) DeleteAuthorization(context context.Context, realmID string, groupName string, targetRealm string, targetGroupName *string, actionReq string) error {
	return deleteAuthorization(c.execNoResult, realmID, groupName, targetRealm, targetGroupName, actionReq)
}

func (c *configurationDBModule) DeleteAllAuthorizationsWithGroup(context context.Context, realmID, groupName string) error {
	return c.execNoResult(deleteAllAuthzWithGroupStmt, realmID, groupName, realmID, groupName)
}

func (c *configurationDBModule) CleanAuthorizationsActionForEveryRealms(context context.Context, realmID string, groupName string, actionReq string) error {
	return c.execNoResult(deleteAuthzEveryRealmsStmt, realmID, groupName, actionReq)
}

func (c *configurationDBModule) CleanAuthorizationsActionForRealm(context context.Context, realmID string, groupName string, targetRealm string, actionReq string) error {
	return c.execNoResult(deleteAuthzRealmStmt, realmID, groupName, actionReq, targetRealm)
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

func (c *configurationDBModule) GetThemeConfiguration(ctx context.Context, realmName string) (configuration.ThemeConfiguration, error) {
	var themeConfig configuration.ThemeConfiguration
	var settings []byte
	row := c.db.QueryRow(selectThemeConfigStmt, realmName)
	err := row.Scan(&settings, &themeConfig.Logo, &themeConfig.Favicon)
	if err != nil {
		if err == sql.ErrNoRows {
			return themeConfig, errorhandler.Error{
				Status:  404,
				Message: ComponentName + "." + msg.MsgErrNotConfigured + "." + realmName,
			}
		}
		c.logger.Warn(ctx, "msg", "Failed to get theme configuration", "err", err.Error(), "realmName", realmName)
		return themeConfig, err
	}
	err = json.Unmarshal(settings, &themeConfig.Settings)
	if err != nil {
		return themeConfig, err
	}
	return themeConfig, nil
}

func (c *configurationDBModule) UpdateThemeConfiguration(ctx context.Context, themeConfig configuration.ThemeConfiguration) error {

	var bytes, _ = json.Marshal(themeConfig.Settings)
	var settingsJSON = string(bytes)

	bytes, _ = json.Marshal(themeConfig.Translations)
	var translationsJSON = string(bytes)

	// Prepare the values for the SQL statement
	args := []any{
		themeConfig.RealmName,
		settingsJSON,
		themeConfig.Logo,
		themeConfig.Favicon,
		translationsJSON,
	}

	// Execute the update/insert statement
	err := c.execNoResult(updateThemeConfigStmt, args...)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update theme configuration", "err", err.Error(), "realmName", themeConfig.RealmName)
		return err
	}
	return nil
}

func (c *configurationDBModule) GetThemeTranslation(ctx context.Context, realmName string, language string) (string, error) {
	var translation sql.NullString
	var sqlRequest = strings.Replace(selectTranslationStmt, "???", language, 1)
	row := c.db.QueryRow(sqlRequest, realmName)
	err := row.Scan(&translation)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errorhandler.Error{
				Status:  404,
				Message: ComponentName + "." + msg.MsgErrNotConfigured + "." + realmName + "." + language,
			}
		}
		c.logger.Warn(ctx, "msg", "Failed to get theme translation", "err", err.Error(), "realmName", realmName, "language", language)
		return "", err
	}

	if !translation.Valid {
		return "{}", nil
	}
	return translation.String, nil
}

func nullableString(value *string) interface{} {
	if value != nil {
		return value
	}
	return nil
}
