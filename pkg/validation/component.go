package validation

import (
	"context"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

var (
	dateLayout = constants.SupportedDateLayouts[0]
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
}

// TokenProvider is the interface to retrieve accessToken to access KC
type TokenProvider interface {
	ProvideToken(ctx context.Context) (string, error)
}

// UsersDetailsDBModule is the interface from the users module
type UsersDetailsDBModule interface {
	StoreOrUpdateUserDetails(ctx context.Context, realm string, user dto.DBUser) error
	GetUserDetails(ctx context.Context, realm string, userID string) (dto.DBUser, error)
	CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
	CreatePendingCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
}

// ArchiveDBModule is the interface from the archive module
type ArchiveDBModule interface {
	StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error
}

// EventsDBModule is the interface of the audit events module
type EventsDBModule interface {
	Store(context.Context, map[string]string) error
	ReportEvent(ctx context.Context, apiCall string, origin string, values ...string) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	GetAdminConfiguration(context.Context, string) (configuration.RealmAdminConfiguration, error)
}

// Component is the register component interface.
type Component interface {
	GetUser(ctx context.Context, realmName string, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName string, userID string, user api.UserRepresentation, txnID *string) error
	CreateCheck(ctx context.Context, realmName string, userID string, check api.CheckRepresentation, txnID *string) error
	CreatePendingCheck(ctx context.Context, realmName string, userID string, pendingChecks api.CheckRepresentation) error
}

// Component is the management component.
type component struct {
	keycloakClient  KeycloakClient
	tokenProvider   TokenProvider
	usersDBModule   UsersDetailsDBModule
	archiveDBModule ArchiveDBModule
	eventsDBModule  database.EventsDBModule
	accredsModule   keycloakb.AccreditationsModule
	configDBModule  ConfigurationDBModule
	logger          keycloakb.Logger
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, tokenProvider TokenProvider, usersDBModule UsersDetailsDBModule, archiveDBModule ArchiveDBModule, eventsDBModule database.EventsDBModule, accredsModule keycloakb.AccreditationsModule, configDBModule ConfigurationDBModule, logger keycloakb.Logger) Component {
	return &component{
		keycloakClient:  keycloakClient,
		tokenProvider:   tokenProvider,
		usersDBModule:   usersDBModule,
		archiveDBModule: archiveDBModule,
		eventsDBModule:  eventsDBModule,
		accredsModule:   accredsModule,
		configDBModule:  configDBModule,
		logger:          logger,
	}
}

func (c *component) getKeycloakUser(ctx context.Context, realmName string, userID string) (kc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't get accessToken for technical user", "err", err.Error())
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}

	kcUser, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't find user in Keycloak", "err", err.Error(), "realmName", realmName, "userID", userID)
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	return kcUser, nil
}

func (c *component) GetUser(ctx context.Context, realmName string, userID string) (api.UserRepresentation, error) {
	var kcUser, err = c.getKeycloakUser(ctx, realmName, userID)
	if err != nil {
		return api.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	if adminConfiguration, err := c.configDBModule.GetAdminConfiguration(ctx, realmName); err != nil {
		return api.UserRepresentation{}, err
	} else if adminConfiguration.ShowGlnEditing != nil && *adminConfiguration.ShowGlnEditing {
		if gln := kcUser.GetAttributeString(constants.AttrbBusinessID); gln == nil {
			return api.UserRepresentation{}, errorhandler.CreateBadRequestError("missing.gln")
		}
	}

	var dbUser dto.DBUser
	dbUser, err = c.usersDBModule.GetUserDetails(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "GetUser: can't find user in keycloak")
		return api.UserRepresentation{}, err
	}

	var res = api.UserRepresentation{}
	res.ImportFromKeycloak(kcUser)
	res.BirthLocation = dbUser.BirthLocation
	res.Nationality = dbUser.Nationality
	res.IDDocumentType = dbUser.IDDocumentType
	res.IDDocumentNumber = dbUser.IDDocumentNumber
	res.IDDocumentCountry = dbUser.IDDocumentCountry

	if dbUser.IDDocumentExpiration != nil {
		expirationTime, err := time.Parse(dateLayout, *dbUser.IDDocumentExpiration)
		if err != nil {
			return api.UserRepresentation{}, err
		}
		res.IDDocumentExpiration = &expirationTime
	}

	return res, nil
}

func (c *component) UpdateUser(ctx context.Context, realmName string, userID string, user api.UserRepresentation, txnID *string) error {
	var validationCtx = &validationContext{
		ctx:       ctx,
		realmName: realmName,
		userID:    userID,
	}

	var err error
	var kcUpdate = needKcProcessing(user)
	var dbUpdate = needDBProcessing(user)
	var shouldRevokeAccreditations bool

	if dbUpdate {
		shouldRevokeAccreditations, err = c.updateUserDatabase(ctx, realmName, userID, user)
		if err != nil {
			return err
		}
	}

	if kcUpdate || shouldRevokeAccreditations {
		err = c.updateUserKeycloak(validationCtx, user, shouldRevokeAccreditations)
		if err != nil {
			return err
		}
	}

	if kcUpdate || dbUpdate {
		// store the API call into the DB
		if txnID != nil {
			c.reportEvent(ctx, "VALIDATION_UPDATE_USER", database.CtEventRealmName, realmName, database.CtEventUserID, userID, "txn_id", *txnID)
		} else {
			c.reportEvent(ctx, "VALIDATION_UPDATE_USER", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
		}

		// archive user
		c.archiveUser(validationCtx, nil)
	}

	return nil
}

func (c *component) updateUserDatabase(ctx context.Context, realmName, userID string, user api.UserRepresentation) (bool, error) {
	var shouldRevokeAccreditations bool
	var userDB = dto.DBUser{
		UserID:            &userID,
		BirthLocation:     user.BirthLocation,
		Nationality:       user.Nationality,
		IDDocumentType:    user.IDDocumentType,
		IDDocumentNumber:  user.IDDocumentNumber,
		IDDocumentCountry: user.IDDocumentCountry,
	}

	if existingUser, err := c.usersDBModule.GetUserDetails(ctx, realmName, userID); err == nil {
		shouldRevokeAccreditations = user.HasUpdateOfAccreditationDependantInformationDB(existingUser)
	}

	if user.IDDocumentExpiration != nil {
		var expiration = (*user.IDDocumentExpiration).Format(dateLayout)
		userDB.IDDocumentExpiration = &expiration
	}

	var err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, realmName, userDB)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update user in DB", "err", err.Error())
		return false, err
	}
	return shouldRevokeAccreditations, nil
}

func (c *component) updateUserKeycloak(validationCtx *validationContext, user api.UserRepresentation, revokeAccreds bool) error {
	var shouldRevokeAccreditations = revokeAccreds

	var kcUser, err = c.loadKeycloakUserCtx(validationCtx)
	if err != nil {
		return err
	}
	keycloakb.ConvertLegacyAttribute(kcUser)
	if !shouldRevokeAccreditations || user.HasUpdateOfAccreditationDependantInformationKC(kcUser) {
		shouldRevokeAccreditations = true
	}

	user.ExportToKeycloak(kcUser)
	if shouldRevokeAccreditations {
		_ = keycloakb.RevokeAccreditations(kcUser)
	}

	return c.updateKeycloakUser(validationCtx)
}

func needKcProcessing(user api.UserRepresentation) bool {
	var kcUserAttrs = []*string{
		user.Gender,
		user.FirstName,
		user.LastName,
		user.Email,
		user.PhoneNumber,
	}

	for _, attr := range kcUserAttrs {
		if attr != nil {
			return true
		}
	}

	return user.BirthDate != nil
}

func needDBProcessing(user api.UserRepresentation) bool {
	var dbUserAttrs = []*string{
		user.BirthLocation,
		user.Nationality,
		user.IDDocumentNumber,
		user.IDDocumentType,
		user.IDDocumentCountry,
	}

	for _, attr := range dbUserAttrs {
		if attr != nil {
			return true
		}
	}

	return user.IDDocumentExpiration != nil
}

func (c *component) CreateCheck(ctx context.Context, realmName string, userID string, check api.CheckRepresentation, txnID *string) error {
	var validationCtx = &validationContext{
		ctx:       ctx,
		realmName: realmName,
		userID:    userID,
	}
	var accessToken string
	var err error

	if check.Operator == nil {
		// If no operator provided, explicitly tells it
		var operator = "none"
		check.Operator = &operator
	}

	dbCheck := check.ConvertToDBCheck()
	err = c.usersDBModule.CreateCheck(ctx, realmName, userID, dbCheck)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store check in DB", "err", err.Error())
		return err
	}

	var eventType = "VALIDATION_STORE_CHECK_INVALID"
	if check.IsIdentificationSuccessful() {
		eventType = "VALIDATION_STORE_CHECK_SUCCESS"

		accessToken, err = c.getAccessToken(validationCtx)
		if err != nil {
			c.logger.Warn(ctx, "msg", "CreateCheck: can't get accessToken for technical user", "err", err.Error())
			return errorhandler.CreateInternalServerError("keycloak")
		}

		var kcUser kc.UserRepresentation
		kcUser, _, err = c.accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, keycloakb.CredsIDNow)
		if err != nil {
			return err
		}
		validationCtx.kcUser = &kcUser
	} else {
		if check.IsIdentificationAborted() {
			eventType = "VALIDATION_STORE_CHECK_ABORTED"
		} else if check.IsIdentificationCanceled() {
			eventType = "VALIDATION_STORE_CHECK_CANCELED"
		}

		_, err = c.loadKeycloakUserCtx(validationCtx)
		if err != nil {
			return err
		}
	}

	err = c.keycloakClient.UpdateUser(*validationCtx.accessToken, realmName, userID, *validationCtx.kcUser)
	if err != nil {
		return err
	}

	// Event
	if txnID != nil {
		c.reportEvent(ctx, eventType, database.CtEventRealmName, realmName, database.CtEventUserID, userID, "operator", *check.Operator, "status", *check.Status, "txn_id", *txnID)
	} else {
		c.reportEvent(ctx, eventType, database.CtEventRealmName, realmName, database.CtEventUserID, userID, "operator", *check.Operator, "status", *check.Status)
	}

	c.archiveUser(validationCtx, []dto.DBCheck{dbCheck})

	return nil
}

func (c *component) CreatePendingCheck(ctx context.Context, realmName string, userID string, pendingChecks api.CheckRepresentation) error {
	return c.usersDBModule.CreatePendingCheck(ctx, realmName, userID, pendingChecks.ConvertToDBCheck())
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		keycloakb.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

type validationContext struct {
	ctx         context.Context
	accessToken *string
	realmName   string
	userID      string
	kcUser      *kc.UserRepresentation
	dbUser      *dto.DBUser
}

func (c *component) getAccessToken(v *validationContext) (string, error) {
	if v.accessToken == nil {
		if accessToken, err := c.tokenProvider.ProvideToken(v.ctx); err == nil {
			v.accessToken = &accessToken
		} else {
			c.logger.Warn(v.ctx, "msg", "Can't get access token", "err", err.Error(), "realm", v.realmName, "user", v.userID)
			return "", err
		}
	}
	return *v.accessToken, nil
}

func (c *component) loadKeycloakUserCtx(v *validationContext) (*kc.UserRepresentation, error) {
	if v.kcUser == nil {
		var accessToken, err = c.getAccessToken(v)
		if err != nil {
			return nil, err
		}
		if kcUser, err := c.keycloakClient.GetUser(accessToken, v.realmName, v.userID); err == nil {
			v.kcUser = &kcUser
		} else {
			c.logger.Warn(v.ctx, "msg", "Can't get user from Keycloak", "err", err.Error(), "realm", v.realmName, "user", v.userID)
			return nil, err
		}
	}
	return v.kcUser, nil
}

func (c *component) updateKeycloakUser(v *validationContext) error {
	accessToken, err := c.getAccessToken(v)
	if err != nil {
		return err
	}

	err = c.keycloakClient.UpdateUser(accessToken, v.realmName, v.userID, *v.kcUser)
	if err != nil {
		c.logger.Warn(v.ctx, "msg", "updateKeycloakUser: can't update user in KC", "err", err.Error(), "realmName", v.realmName, "userID", v.userID)
		return errorhandler.CreateInternalServerError("keycloak")
	}
	return nil
}

func (c *component) getDbUser(v *validationContext) (*dto.DBUser, error) {
	if v.dbUser == nil {
		if dbUser, err := c.usersDBModule.GetUserDetails(v.ctx, v.realmName, v.userID); err == nil {
			v.dbUser = &dbUser
		} else {
			c.logger.Warn(v.ctx, "msg", "Can't get user from database", "err", err.Error(), "realm", v.realmName, "user", v.userID)
			return nil, err
		}
	}
	return v.dbUser, nil
}

func (c *component) getUserWithAccreditations(v *validationContext) (*kc.UserRepresentation, error) {
	if v.kcUser == nil {
		var accessToken, err = c.getAccessToken(v)
		if err != nil {
			return nil, err
		}
		var kcUser kc.UserRepresentation
		if kcUser, _, err = c.accredsModule.GetUserAndPrepareAccreditations(v.ctx, accessToken, v.realmName, v.userID, keycloakb.CredsIDNow); err == nil {
			v.kcUser = &kcUser
		} else {
			return nil, err
		}
	}
	return v.kcUser, nil
}

func (c *component) archiveUser(v *validationContext, checks []dto.DBCheck) {
	var kcUser, err = c.loadKeycloakUserCtx(v)
	if err != nil {
		return
	}
	var dbUser *dto.DBUser
	dbUser, err = c.getDbUser(v)
	if err != nil {
		return
	}

	var archiveUser = dto.ToArchiveUserRepresentation(*kcUser)
	archiveUser.SetDetails(*dbUser)
	archiveUser.Checks = checks
	c.archiveDBModule.StoreUserDetails(v.ctx, v.realmName, archiveUser)
}
