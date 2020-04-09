package validation

import (
	"context"
	"time"

	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/cloudtrust/keycloak-client/toolbox"
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

// UsersDBModule is the interface from the users module
type UsersDBModule interface {
	StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error
	GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error)
	CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
}

// EventsDBModule is the interface of the audit events module
type EventsDBModule interface {
	Store(context.Context, map[string]string) error
	ReportEvent(ctx context.Context, apiCall string, origin string, values ...string) error
}

// Component is the register component interface.
type Component interface {
	GetUser(ctx context.Context, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, userID string, user api.UserRepresentation) error
	CreateCheck(ctx context.Context, userID string, check api.CheckRepresentation) error
}

// Component is the management component.
type component struct {
	socialRealmName string
	keycloakClient  KeycloakClient
	tokenProvider   toolbox.OidcTokenProvider
	usersDBModule   keycloakb.UsersDBModule
	eventsDBModule  database.EventsDBModule
	accredsModule   keycloakb.AccreditationsModule
	logger          internal.Logger
}

// NewComponent returns the management component.
func NewComponent(socialRealmName string, keycloakClient KeycloakClient, tokenProvider TokenProvider, usersDBModule keycloakb.UsersDBModule, eventsDBModule database.EventsDBModule, accredsModule keycloakb.AccreditationsModule, logger internal.Logger) Component {
	return &component{
		socialRealmName: socialRealmName,
		keycloakClient:  keycloakClient,
		tokenProvider:   tokenProvider,
		usersDBModule:   usersDBModule,
		eventsDBModule:  eventsDBModule,
		accredsModule:   accredsModule,
		logger:          logger,
	}
}

func (c *component) getKeycloakUser(ctx context.Context, userID string) (kc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't get accessToken for technical user", "err", err.Error())
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}

	kcUser, err := c.keycloakClient.GetUser(accessToken, c.socialRealmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "getKeycloakUser: can't find user in Keycloak", "err", err.Error())
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	return kcUser, nil
}

func (c *component) updateKeycloakUser(ctx context.Context, userID string, userKC kc.UserRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "updateKeycloakUser: can't get accessToken for technical user", "err", err.Error())
		return errorhandler.CreateInternalServerError("keycloak")
	}

	err = c.keycloakClient.UpdateUser(accessToken, c.socialRealmName, userID, userKC)
	if err != nil {
		c.logger.Warn(ctx, "msg", "updateKeycloakUser: can't update user in KC", "err", err.Error(), "userID", userID)
		return errorhandler.CreateInternalServerError("keycloak")
	}
	return nil
}

func (c *component) GetUser(ctx context.Context, userID string) (api.UserRepresentation, error) {
	var kcUser, err = c.getKeycloakUser(ctx, userID)
	if err != nil {
		return api.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	var dbUser *dto.DBUser
	dbUser, err = c.usersDBModule.GetUser(ctx, c.socialRealmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "GetUser: can't find user in keycloak")
		return api.UserRepresentation{}, err
	}

	if dbUser == nil {
		dbUser = &dto.DBUser{}
	}

	var res = api.UserRepresentation{}
	res.ImportFromKeycloak(kcUser)
	res.BirthLocation = dbUser.BirthLocation
	res.IDDocumentType = dbUser.IDDocumentType
	res.IDDocumentNumber = dbUser.IDDocumentNumber

	if dbUser.IDDocumentExpiration != nil {
		expirationTime, err := time.Parse(dateLayout, *dbUser.IDDocumentExpiration)
		if err != nil {
			return api.UserRepresentation{}, err
		}
		res.IDDocumentExpiration = &expirationTime
	}

	return res, nil
}

func (c *component) UpdateUser(ctx context.Context, userID string, user api.UserRepresentation) error {
	var err error
	var kcUpdate = needKcUserUpdate(user)
	var dbUpdate = needDBUserUpdate(user)

	if kcUpdate {
		kcUser, err := c.getKeycloakUser(ctx, userID)
		if err != nil {
			return err
		}
		keycloakb.ConvertLegacyAttribute(&kcUser)

		user.ExportToKeycloak(&kcUser)
		err = c.updateKeycloakUser(ctx, userID, kcUser)
		if err != nil {
			return err
		}
	}

	if dbUpdate {
		var uID = userID

		var userDB = dto.DBUser{
			UserID:           &uID,
			IDDocumentType:   user.IDDocumentType,
			IDDocumentNumber: user.IDDocumentNumber,
		}

		if user.IDDocumentExpiration != nil {
			var expiration = (*user.IDDocumentExpiration).Format(dateLayout)
			userDB.IDDocumentExpiration = &expiration
		}

		err = c.usersDBModule.StoreOrUpdateUser(ctx, c.socialRealmName, userDB)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't update user in DB", "err", err.Error())
			return err
		}
	}

	if kcUpdate || dbUpdate {
		// store the API call into the DB
		c.reportEvent(ctx, "VALIDATION_UPDATE_USER", database.CtEventRealmName, c.socialRealmName, database.CtEventUserID, userID)
	}

	return nil
}

func needKcUserUpdate(user api.UserRepresentation) bool {
	var kcUserAttrs = []*string{
		user.Gender,
		user.FirstName,
		user.LastName,
		user.EmailAddress,
		user.PhoneNumber,
	}

	for _, attr := range kcUserAttrs {
		if attr != nil {
			return true
		}
	}

	if user.BirthDate != nil {
		return true
	}

	return false
}

func needDBUserUpdate(user api.UserRepresentation) bool {
	var dbUserAttrs = []*string{
		user.BirthLocation,
		user.IDDocumentNumber,
		user.IDDocumentType,
	}

	for _, attr := range dbUserAttrs {
		if attr != nil {
			return true
		}
	}

	if user.IDDocumentExpiration != nil {
		return true
	}

	return false
}

func (c *component) CreateCheck(ctx context.Context, userID string, check api.CheckRepresentation) error {
	var accessToken string
	var err error

	dbCheck := check.ConvertToDBCheck()
	err = c.usersDBModule.CreateCheck(ctx, c.socialRealmName, userID, dbCheck)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store check in DB", "err", err.Error())
		return err
	}

	if check.IsIdentificationSuccessful() {
		accessToken, err = c.tokenProvider.ProvideToken(ctx)
		if err != nil {
			c.logger.Warn(ctx, "msg", "CreateCheck: can't get accessToken for technical user", "err", err.Error())
			return errorhandler.CreateInternalServerError("keycloak")
		}

		var kcUser kc.UserRepresentation
		kcUser, _, err = c.accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, c.socialRealmName, userID, keycloakb.CredsIDNow)
		if err != nil {
			return err
		}

		err = c.keycloakClient.UpdateUser(accessToken, c.socialRealmName, userID, kcUser)
		if err != nil {
			return err
		}
	}

	// Event
	c.reportEvent(ctx, "VALIDATION_STORE_CHECK", database.CtEventRealmName, c.socialRealmName,
		database.CtEventUserID, userID, "operator", *check.Operator, "status", *check.Status)

	return nil
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}
