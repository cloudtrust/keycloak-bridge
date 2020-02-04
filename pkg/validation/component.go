package validation

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudtrust/keycloak-client"

	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	messages "github.com/cloudtrust/keycloak-bridge/internal/messages"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
}

type UsersDBModule interface {
}

type EventsDBModule interface {
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
	tokenProvider   keycloak.OidcTokenProvider
	usersDBModule   keycloakb.UsersDBModule
	eventsDBModule  database.EventsDBModule
	logger          internal.Logger
}

// NewComponent returns the management component.
func NewComponent(socialRealmName string, keycloakClient KeycloakClient, usersDBModule keycloakb.UsersDBModule, eventsDBModule database.EventsDBModule, logger internal.Logger) Component {
	return &component{
		socialRealmName: socialRealmName,
		keycloakClient:  keycloakClient,
		usersDBModule:   usersDBModule,
		eventsDBModule:  eventsDBModule,
		logger:          logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func (c *component) GetUser(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	// TODO
	// retrieve KcUSer
	// retrieve user PII, and combine
	// return
	var kcUser, err = c.getUserByUsername(accessToken, c.socialRealmName, c.socialRealmName, username)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}

	var dbUser *dto.DBUser
	dbUser, err = c.usersDBModule.GetUser(ctx, c.socialRealmName, *kcUser.Id)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in keycloak")
		return apikyc.UserRepresentation{}, err
	}

	if dbUser == nil {
		dbUser = &dto.DBUser{}
	}

	var res = apikyc.UserRepresentation{
		BirthLocation:        dbUser.BirthLocation,
		IDDocumentType:       dbUser.IDDocumentType,
		IDDocumentNumber:     dbUser.IDDocumentNumber,
		IDDocumentExpiration: dbUser.IDDocumentExpiration,
		Validation:           dbUser.LastValidation(),
	}
	res.ImportFromKeycloak(&kcUser)

	return res, nil
}

func (c *component) UpdateUser(ctx context.Context, userID string, user api.UserRepresentation) error {

	/*
		check if there is some changes which must be put in KC
		if yes -> update user KC

		if changes in PII -> update DB

		Event if there any changes

	*/

	// Gets user from Keycloak
	var kcUser kc.UserRepresentation
	kcUser, err = c.keycloakClient.GetUser(accessToken, c.socialRealmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user from Keycloak", "err", err.Error())
		return err
	}

	// Some parameters might not be updated by operator
	user.UserID = &userID
	user.EmailAddress = nil
	user.PhoneNumber = nil
	user.EmailAddressVerified = nil
	user.PhoneNumberVerified = nil
	user.Username = kcUser.Username

	if kcUser.EmailVerified == nil || !*kcUser.EmailVerified {
		c.logger.Warn(ctx, "msg", "Can't validate user with unverified email", "uid", userID)
		return errorhandler.CreateBadRequestError(messages.MsgErrUnverified + "." + messages.Email)
	}
	if !isPhoneNumberVerified(kcUser.Attributes) {
		c.logger.Warn(ctx, "msg", "Can't validate user with unverified phone number", "uid", userID)
		return errorhandler.CreateBadRequestError(messages.MsgErrUnverified + "." + messages.PhoneNumber)
	}

	// Gets user from database
	var dbUser *dto.DBUser
	dbUser, err = c.usersDBModule.GetUser(ctx, c.socialRealmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user from database", "err", err.Error())
		return err
	}
	if dbUser == nil {
		c.logger.Warn(ctx, "msg", "User not found in database", "uid", userID)
		return errorhandler.CreateNotFoundError("user")
	}

	var now = time.Now()
	var validation = dto.DBValidation{
		Date:         &now,
		OperatorName: &operatorName,
		Comment:      user.Comment,
	}
	dbUser.BirthLocation = user.BirthLocation
	dbUser.IDDocumentType = user.IDDocumentType
	dbUser.IDDocumentNumber = user.IDDocumentNumber
	dbUser.IDDocumentExpiration = user.IDDocumentExpiration
	dbUser.Validations = append(dbUser.Validations, validation)

	user.ExportToKeycloak(&kcUser)
	err = c.keycloakClient.UpdateUser(accessToken, c.socialRealmName, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return err
	}

	// Store user in database
	err = c.usersDBModule.StoreOrUpdateUser(ctx, c.socialRealmName, *dbUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "VALIDATE_USER", database.CtEventRealmName, c.socialRealmName, database.CtEventUserID, userID, database.CtEventUsername, *user.Username)

	return nil
}

func (c *component) CreateCheck(ctx context.Context, userID string, check api.CheckRepresentation) error {

	// Put in DB

	// Event
	return nil
}

func isPhoneNumberVerified(attribs *map[string][]string) bool {
	if attribs == nil {
		return false
	}
	if value, ok := (*attribs)["phoneNumberVerified"]; ok && len(value) > 0 {
		verified, err := strconv.ParseBool(value[0])
		return verified && err == nil
	}
	return false
}
