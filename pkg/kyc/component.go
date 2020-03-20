package kyc

import (
	"context"
	"time"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/keycloak-client"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
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
	GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error)
	GetUser(ctx context.Context, userID string) (apikyc.UserRepresentation, error)
	GetUserByUsername(ctx context.Context, username string) (apikyc.UserRepresentation, error)
	ValidateUser(ctx context.Context, userID string, user apikyc.UserRepresentation) error
}

// Component is the management component.
type component struct {
	socialRealmName string
	keycloakClient  KeycloakClient
	usersDBModule   keycloakb.UsersDBModule
	eventsDBModule  database.EventsDBModule
	accredsModule   keycloakb.AccreditationsModule
	logger          internal.Logger
}

// NewComponent returns the management component.
func NewComponent(socialRealmName string, keycloakClient KeycloakClient, usersDBModule UsersDBModule, eventsDBModule EventsDBModule, accredsModule keycloakb.AccreditationsModule, logger internal.Logger) Component {
	return &component{
		socialRealmName: socialRealmName,
		keycloakClient:  keycloakClient,
		usersDBModule:   usersDBModule,
		eventsDBModule:  eventsDBModule,
		accredsModule:   accredsModule,
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

func (c *component) GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error) {
	var apiActions = []apikyc.ActionRepresentation{}

	for _, action := range actions {
		var name = action.Name
		var scope = string(action.Scope)

		apiActions = append(apiActions, apikyc.ActionRepresentation{
			Name:  &name,
			Scope: &scope,
		})
	}

	return apiActions, nil
}

func (c *component) GetUserByUsername(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var group, err = c.getGroupByName(accessToken, c.socialRealmName, "end_user")
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}
	var kcUser keycloak.UserRepresentation
	kcUser, err = c.getUserByUsername(accessToken, c.socialRealmName, c.socialRealmName, username, *group.Id)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)
	return c.getUser(ctx, *kcUser.Id, kcUser)
}

func (c *component) GetUser(ctx context.Context, userID string) (apikyc.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var kcUser, err = c.keycloakClient.GetUser(accessToken, c.socialRealmName, userID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)
	return c.getUser(ctx, userID, kcUser)
}

func (c *component) getUser(ctx context.Context, userID string, kcUser kc.UserRepresentation) (apikyc.UserRepresentation, error) {
	var dbUser, err = c.usersDBModule.GetUser(ctx, c.socialRealmName, *kcUser.Id)
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
	}
	res.ImportFromKeycloak(&kcUser)

	return res, nil
}

func (c *component) ValidateUser(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var operatorName = ctx.Value(cs.CtContextUsername).(string)

	// Validate input request
	var err = user.Validate()
	if err != nil {
		c.logger.Info(ctx, "err", err.Error())
		return err
	}

	// Gets user from Keycloak
	var kcUser kc.UserRepresentation
	kcUser, _, err = c.accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, c.socialRealmName, userID, configuration.CheckKeyPhysical)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user/accreditations", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	// Some parameters might not be updated by operator
	user.UserID = &userID
	user.EmailAddress = nil
	user.PhoneNumber = nil
	user.EmailAddressVerified = nil
	user.PhoneNumberVerified = nil
	user.Username = kcUser.Username

	if kcUser.EmailVerified == nil || !*kcUser.EmailVerified {
		c.logger.Warn(ctx, "msg", "Can't validate user with unverified email", "uid", userID)
		return errorhandler.CreateBadRequestError(constants.MsgErrUnverified + "." + constants.Email)
	}
	if verified, verifiedErr := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); verifiedErr != nil || verified == nil || !*verified {
		c.logger.Warn(ctx, "msg", "Can't validate user with unverified phone number", "uid", userID)
		return errorhandler.CreateBadRequestError(constants.MsgErrUnverified + "." + constants.PhoneNumber)
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

	dbUser.BirthLocation = user.BirthLocation
	dbUser.IDDocumentType = user.IDDocumentType
	dbUser.IDDocumentNumber = user.IDDocumentNumber
	dbUser.IDDocumentExpiration = user.IDDocumentExpiration

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

	// Store check in database
	var validation = dto.DBCheck{
		Operator: &operatorName,
		DateTime: &now,
		Status:   ptr("VERIFIED"),
		Type:     ptr("IDENTITY_CHECK"),
		Nature:   ptr("PHYSICAL_CHECK"),
		Comment:  user.Comment,
	}

	err = c.usersDBModule.CreateCheck(ctx, c.socialRealmName, userID, validation)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store validation check in database", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "VALIDATE_USER", database.CtEventRealmName, c.socialRealmName, database.CtEventUserID, userID, database.CtEventUsername, *user.Username)

	return nil
}

func (c *component) getGroupByName(accessToken, realmName, groupName string) (kc.GroupRepresentation, error) {
	var groups, err = c.keycloakClient.GetGroups(accessToken, realmName)
	if err != nil {
		return kc.GroupRepresentation{}, err
	}
	for _, grp := range groups {
		if *grp.Name == groupName {
			return grp, nil
		}
	}
	return kc.GroupRepresentation{}, errorhandler.CreateNotFoundError("group")
}

func (c *component) getUserByUsername(accessToken, reqRealmName, targetRealmName, username, groupID string) (kc.UserRepresentation, error) {
	var kcUsers, err = c.keycloakClient.GetUsers(accessToken, reqRealmName, targetRealmName, "username", username, "groupId", groupID)
	if err != nil {
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	if kcUsers.Count == nil || *kcUsers.Count != 1 || kcUsers.Users[0].Username == nil || *kcUsers.Users[0].Username != username {
		return kc.UserRepresentation{}, errorhandler.CreateNotFoundError("user")
	}

	var res = kcUsers.Users[0]
	keycloakb.ConvertLegacyAttribute(&res)
	return res, nil
}

func ptr(value string) *string {
	return &value
}
