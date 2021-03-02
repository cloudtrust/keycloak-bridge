package kyc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/validation"
	"github.com/cloudtrust/keycloak-client"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/cloudtrust/keycloak-client/toolbox"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	SendSmsCode(accessToken string, realmName string, userID string) (kc.SmsCodeRepresentation, error)
	SendConsentCodeSMS(accessToken string, realmName string, userID string) error
	CheckConsentCodeSMS(accessToken string, realmName string, userID string, consentCode string) error
}

// UsersDetailsDBModule is the interface from the users module
type UsersDetailsDBModule interface {
	StoreOrUpdateUserDetails(ctx context.Context, realm string, user dto.DBUser) error
	GetUserDetails(ctx context.Context, realm string, userID string) (dto.DBUser, error)
	CreateCheck(ctx context.Context, realm string, userID string, check dto.DBCheck) error
	GetChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error)
}

// ArchiveDBModule is the interface from the archive module
type ArchiveDBModule interface {
	StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error
}

// ConfigDBModule is the interface from the configuration DB module
type ConfigDBModule interface {
	GetAdminConfiguration(ctx context.Context, realmID string) (configuration.RealmAdminConfiguration, error)
}

// EventsDBModule is the interface of the audit events module
type EventsDBModule interface {
	Store(context.Context, map[string]string) error
	ReportEvent(ctx context.Context, apiCall string, origin string, values ...string) error
}

// Component is the register component interface.
type Component interface {
	GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error)
	GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error)
	GetUserByUsernameInSocialRealm(ctx context.Context, username string) (apikyc.UserRepresentation, error)
	ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error
	ValidateUser(ctx context.Context, realm string, userID string, user apikyc.UserRepresentation) error
	SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error
	SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error)
}

// Component is the management component.
type component struct {
	tokenProvider   toolbox.OidcTokenProvider
	socialRealmName string
	keycloakClient  KeycloakClient
	usersDBModule   UsersDetailsDBModule
	archiveDBModule ArchiveDBModule
	configDBModule  ConfigDBModule
	eventsDBModule  database.EventsDBModule
	accredsModule   keycloakb.AccreditationsModule
	logger          internal.Logger
}

// NewComponent returns the management component.
func NewComponent(tokenProvider toolbox.OidcTokenProvider, socialRealmName string, keycloakClient KeycloakClient, usersDBModule UsersDetailsDBModule, archiveDBModule ArchiveDBModule, configDBModule ConfigDBModule, eventsDBModule EventsDBModule, accredsModule keycloakb.AccreditationsModule, logger internal.Logger) Component {
	return &component{
		tokenProvider:   tokenProvider,
		socialRealmName: socialRealmName,
		keycloakClient:  keycloakClient,
		usersDBModule:   usersDBModule,
		archiveDBModule: archiveDBModule,
		configDBModule:  configDBModule,
		eventsDBModule:  eventsDBModule,
		accredsModule:   accredsModule,
		logger:          logger,
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

func (c *component) GetUserByUsernameInSocialRealm(ctx context.Context, username string) (apikyc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}

	group, err := c.getGroupByName(accessToken, c.socialRealmName, "end_user")
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}

	var kcUser keycloak.UserRepresentation
	kcUser, err = c.getUserByUsername(accessToken, c.socialRealmName, c.socialRealmName, username, *group.ID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	var res apikyc.UserRepresentation
	res, err = c.getUser(ctx, *kcUser.ID, kcUser)
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}
	// At this point, we shall not provide too many information
	res = apikyc.UserRepresentation{
		ID:          res.ID,
		Username:    res.Username,
		FirstName:   res.FirstName,
		LastName:    res.LastName,
		PhoneNumber: res.PhoneNumber,
	}
	if res.PhoneNumber != nil {
		var phoneNumber = validation.ObfuscatePhoneNumber(*res.PhoneNumber)
		res.PhoneNumber = &phoneNumber
	}
	return res, nil
}

func (c *component) createConsentError(errorType string) error {
	return errorhandler.Error{
		Status:  430,
		Message: fmt.Sprintf("%s.%s.consent", errorhandler.GetEmitter(), errorType),
	}
}

func (c *component) checkUserConsent(ctx context.Context, accessToken string, realm string, userID string, consentCode *string) error {
	var rac, err = c.configDBModule.GetAdminConfiguration(ctx, realm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm admin configuration", "realm", realm, "err", err.Error())
		return err
	}

	if rac.ConsentRequired != nil && *rac.ConsentRequired {
		// Consent is required
		if consentCode == nil {
			return c.createConsentError(errorhandler.MsgErrMissingParam)
		}
		if err = c.keycloakClient.CheckConsentCodeSMS(accessToken, realm, userID, *consentCode); err != nil {
			switch e := err.(type) {
			case kc.HTTPError:
				if e.HTTPStatus == http.StatusForbidden {
					return c.createConsentError(errorhandler.MsgErrInvalidQueryParam)
				}
			}
			return err
		}
	}

	return nil
}

func (c *component) GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}

	err = c.checkUserConsent(ctx, accessToken, c.socialRealmName, userID, consentCode)
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}

	kcUser, err := c.keycloakClient.GetUser(accessToken, c.socialRealmName, userID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)
	return c.getUser(ctx, userID, kcUser)
}

func (c *component) getUser(ctx context.Context, userID string, kcUser kc.UserRepresentation) (apikyc.UserRepresentation, error) {
	var dbUser, err = c.usersDBModule.GetUserDetails(ctx, c.socialRealmName, *kcUser.ID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in keycloak")
		return apikyc.UserRepresentation{}, err
	}

	var res = apikyc.UserRepresentation{
		BirthLocation:        dbUser.BirthLocation,
		Nationality:          dbUser.Nationality,
		IDDocumentType:       dbUser.IDDocumentType,
		IDDocumentNumber:     dbUser.IDDocumentNumber,
		IDDocumentExpiration: dbUser.IDDocumentExpiration,
		IDDocumentCountry:    dbUser.IDDocumentCountry,
	}
	res.ImportFromKeycloak(ctx, &kcUser, c.logger)

	return res, nil
}

func (c *component) ValidateUser(ctx context.Context, realmName string, userID string, user apikyc.UserRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.validateUser(ctx, accessToken, realmName, userID, user, nil)
}

func (c *component) ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}

	err = c.checkUserConsent(ctx, accessToken, c.socialRealmName, userID, consentCode)
	if err != nil {
		return err
	}

	return c.validateUser(ctx, accessToken, c.socialRealmName, userID, user, consentCode)
}

func (c *component) validateUser(ctx context.Context, accessToken string, realmName string, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	var operatorName = ctx.Value(cs.CtContextUsername).(string)

	// Gets user from Keycloak
	var kcUser kc.UserRepresentation
	kcUser, _, err := c.accredsModule.GetUserAndPrepareAccreditations(ctx, accessToken, realmName, userID, configuration.CheckKeyPhysical)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get user/accreditations", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	// Some parameters might not be updated by operator
	user.ID = &userID
	user.Email = nil
	user.PhoneNumber = nil
	user.EmailVerified = nil
	user.PhoneNumberVerified = nil
	user.Username = kcUser.Username

	err = c.ensureContactVerified(ctx, kcUser)
	if err != nil {
		return err
	}

	// Gets user from database
	dbUser, err := c.usersDBModule.GetUserDetails(ctx, realmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get user from database", "err", err.Error())
		return err
	}

	var now = time.Now()

	user.ExportToDBUser(&dbUser)
	user.ExportToKeycloak(&kcUser)
	err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return err
	}

	// Store user in database
	err = c.usersDBModule.StoreOrUpdateUserDetails(ctx, realmName, dbUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store user details in database", "err", err.Error())
		return err
	}

	// Store check in database
	var validation = dto.DBCheck{
		Operator:  &operatorName,
		DateTime:  &now,
		Status:    ptr("VERIFIED"),
		Type:      ptr("IDENTITY_CHECK"),
		Nature:    ptr("PHYSICAL_CHECK"),
		Comment:   user.Comment,
		ProofType: nil,
		ProofData: nil,
	}

	if user.Attachments != nil && len(*user.Attachments) > 0 {
		validation.ProofType = (*user.Attachments)[0].ContentType
		validation.ProofData = (*user.Attachments)[0].Content
	}
	err = c.usersDBModule.CreateCheck(ctx, realmName, userID, validation)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't store validation check in database", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "VALIDATE_USER", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, *user.Username)

	var archiveUser = dto.ToArchiveUserRepresentation(kcUser)
	archiveUser.SetDetails(dbUser)
	if archiveUser.Checks, err = c.usersDBModule.GetChecks(ctx, realmName, userID); err != nil {
		c.logger.Warn(ctx, "msg", "Could not get user checks from database", "err", err.Error(), "realm", realmName, "user", userID)
	}

	err = c.archiveDBModule.StoreUserDetails(ctx, realmName, archiveUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to archive user details", "err", err.Error())
	}

	return nil
}

func (c *component) ensureContactVerified(ctx context.Context, kcUser kc.UserRepresentation) error {
	var emailVerifiedMissing = kcUser.EmailVerified == nil || !*kcUser.EmailVerified
	var phoneNumberVerifiedMissing = false
	if verified, verifiedErr := kcUser.GetAttributeBool(constants.AttrbPhoneNumberVerified); verifiedErr != nil || verified == nil || !*verified {
		phoneNumberVerifiedMissing = true
	}

	if !emailVerifiedMissing && !phoneNumberVerifiedMissing {
		// Avoid to access database if not necessary
		return nil
	}

	var realmName = ctx.Value(cs.CtContextRealm).(string)
	if config, err := c.configDBModule.GetAdminConfiguration(ctx, realmName); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get admin configuration", "realm", realmName, "err", err.Error())
		return err
	} else if config.NeedVerifiedContact != nil && !*config.NeedVerifiedContact {
		return nil
	}

	if emailVerifiedMissing {
		c.logger.Warn(ctx, "msg", "Can't validate user with unverified email", "uid", *kcUser.ID)
		return errorhandler.CreateBadRequestError(constants.MsgErrUnverified + "." + constants.Email)
	}

	c.logger.Warn(ctx, "msg", "Can't validate user with unverified phone number", "uid", *kcUser.ID)
	return errorhandler.CreateBadRequestError(constants.MsgErrUnverified + "." + constants.PhoneNumber)
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

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventsDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
	}
}

func ptr(value string) *string {
	return &value
}

func (c *component) SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error {
	var accessToken, err = c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}

	err = c.keycloakClient.SendConsentCodeSMS(accessToken, c.socialRealmName, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't send consent SMS", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "SMS_CONSENT", database.CtEventRealmName, c.socialRealmName, database.CtEventUserID, userID)

	return nil
}

func (c *component) SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error) {
	var accessToken, err = c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return "", err
	}

	return c.sendSmsCode(ctx, accessToken, c.socialRealmName, userID)
}

func (c *component) sendSmsCode(ctx context.Context, accessToken string, realm string, userID string) (string, error) {
	smsCodeKc, err := c.keycloakClient.SendSmsCode(accessToken, realm, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "SMS_CHALLENGE", database.CtEventRealmName, realm, database.CtEventUserID, userID)

	return *smsCodeKc.Code, err
}
