package kyc

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/validation"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"

	"github.com/cloudtrust/common-service/v2/events"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/security"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	"github.com/google/uuid"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	SendSmsCode(accessToken string, realmName string, userID string) (kc.SmsCodeRepresentation, error)
	SendConsentCodeSMS(accessToken string, realmName string, userID string) error
	CheckConsentCodeSMS(accessToken string, realmName string, userID string, consentCode string) error
}

// ArchiveDBModule is the interface from the archive module
type ArchiveDBModule interface {
	StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error
}

// ConfigDBModule is the interface from the configuration DB module
type ConfigDBModule interface {
	GetAdminConfiguration(ctx context.Context, realmID string) (configuration.RealmAdminConfiguration, error)
}

// EventsReporterModule is the interface of the audit events module
type EventsReporterModule interface {
	ReportEvent(ctx context.Context, event events.Event)
}

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	NotifyCheck(ctx context.Context, check accreditationsclient.CheckRepresentation) error
}

// UserProfileCache interface
type UserProfileCache interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// Component is the register component interface.
type Component interface {
	GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error)
	GetUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error)
	GetUserProfileInSocialRealm(ctx context.Context) (apicommon.ProfileRepresentation, error)
	GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error)
	GetUserByUsernameInSocialRealm(ctx context.Context, username string) (apikyc.UserRepresentation, error)
	GetUser(ctx context.Context, realmName string, userID string, consentCode *string) (apikyc.UserRepresentation, error)
	GetUserByUsername(ctx context.Context, realmName string, username string) (apikyc.UserRepresentation, error)
	ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error
	ValidateUser(ctx context.Context, realm string, userID string, user apikyc.UserRepresentation, consentCode *string) error
	SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error
	SendSmsConsentCode(ctx context.Context, realmName string, userID string) error
	SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error)
	SendSmsCode(ctx context.Context, realmName string, userID string) (string, error)

	ValidateUserBasicID(ctx context.Context, userID string, user apikyc.UserRepresentation) error /***TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED***/
}

// Component is the management component.
type component struct {
	tokenProvider             toolbox.OidcTokenProvider
	socialRealmName           string
	keycloakClient            KeycloakClient
	profileCache              UserProfileCache
	archiveDBModule           ArchiveDBModule
	configDBModule            ConfigDBModule
	auditEventsReporterModule EventsReporterModule
	accredsServiceClient      AccreditationsServiceClient
	logger                    log.Logger
	originEvent               string
}

const (
	targetUserGroup = "end_user"
)

// NewComponent returns the management component.
func NewComponent(tokenProvider toolbox.OidcTokenProvider, socialRealmName string, keycloakClient KeycloakClient, profileCache UserProfileCache, archiveDBModule ArchiveDBModule, configDBModule ConfigDBModule, auditEventsReporterModule EventsReporterModule, accredsServiceClient AccreditationsServiceClient, logger log.Logger) Component {
	return &component{
		tokenProvider:             tokenProvider,
		socialRealmName:           socialRealmName,
		keycloakClient:            keycloakClient,
		profileCache:              profileCache,
		archiveDBModule:           archiveDBModule,
		configDBModule:            configDBModule,
		auditEventsReporterModule: auditEventsReporterModule,
		accredsServiceClient:      accredsServiceClient,
		logger:                    logger,
		originEvent:               "back-office",
	}
}

func (c *component) GetActions(ctx context.Context) ([]apikyc.ActionRepresentation, error) {
	var apiActions = []apikyc.ActionRepresentation{}

	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.KycAPI) {
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
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}

	var groupID *string
	group, err := c.getGroupByName(accessToken, c.socialRealmName, targetUserGroup)
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}
	groupID = group.ID

	return c.getUserByUsernameGeneric(ctx, accessToken, c.socialRealmName, username, groupID)
}

func (c *component) GetUserByUsername(ctx context.Context, realmName string, username string) (apikyc.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	// Corporate version does not specify a group ID: groups will be checked when returning result to authorization layer
	var user, err = c.getUserByUsernameGeneric(ctx, accessToken, realmName, username, nil)
	if err != nil {
		return user, err
	}

	var groups []kc.GroupRepresentation
	groups, err = c.keycloakClient.GetGroupsOfUser(accessToken, realmName, *user.ID)
	if err != nil {
		return user, err
	}
	if len(groups) > 0 {
		var userGroups []string
		for _, group := range groups {
			userGroups = append(userGroups, *group.Name)
		}
		user.Groups = &userGroups
	}

	return user, err
}

func (c *component) getUserByUsernameGeneric(ctx context.Context, accessToken string, realmName string, username string, groupID *string) (apikyc.UserRepresentation, error) {
	var kcUser, err = c.getUserByUsername(accessToken, realmName, realmName, username, groupID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	profile, err := c.profileCache.GetRealmUserProfile(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "failed to load user profile")
		return apikyc.UserRepresentation{}, err
	}

	var res apikyc.UserRepresentation
	res.ImportFromKeycloak(ctx, &kcUser, profile, c.logger)
	// At this point, we shall not provide too many information
	res = apikyc.UserRepresentation{
		ID:                  res.ID,
		Username:            res.Username,
		FirstName:           res.FirstName,
		LastName:            res.LastName,
		EmailVerified:       res.EmailVerified,
		PhoneNumber:         res.PhoneNumber,
		PhoneNumberVerified: res.PhoneNumberVerified,
		Accreditations:      res.Accreditations,
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

func (c *component) checkUserConsent(ctx context.Context, accessToken string, confRealm string, targetRealm string, userID string, consentCode *string) error {
	var rac, err = c.configDBModule.GetAdminConfiguration(ctx, confRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm admin configuration", "realm", confRealm, "err", err.Error())
		return err
	}

	if c.consentRequired(rac, targetRealm) {
		// Consent is required
		if consentCode == nil {
			return c.createConsentError(errorhandler.MsgErrMissingParam)
		}
		if err = c.keycloakClient.CheckConsentCodeSMS(accessToken, targetRealm, userID, *consentCode); err != nil {
			switch e := err.(type) {
			case kc.ClientDetailedError:
				if e.HTTPStatus == 430 {
					return c.createConsentError(errorhandler.MsgErrInvalidQueryParam)
				}
			}
			return err
		}
	}

	return nil
}

func (c *component) consentRequired(rac configuration.RealmAdminConfiguration, targetRealm string) bool {
	if targetRealm == c.socialRealmName {
		return rac.ConsentRequiredSocial != nil && *rac.ConsentRequiredSocial
	}
	return rac.ConsentRequiredCorporate != nil && *rac.ConsentRequiredCorporate
}

func (c *component) GetUserProfileInSocialRealm(ctx context.Context) (apicommon.ProfileRepresentation, error) {
	return c.GetUserProfile(ctx, c.socialRealmName)
}

func (c *component) GetUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error) {
	var profile, err = c.profileCache.GetRealmUserProfile(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get users profile", "err", err.Error())
		return apicommon.ProfileRepresentation{}, err
	}

	return apicommon.ProfileToAPI(profile, apiName), nil
}

func (c *component) GetUserInSocialRealm(ctx context.Context, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return apikyc.UserRepresentation{}, err
	}
	var confRealm = ctx.Value(cs.CtContextRealm).(string)
	return c.getUserGeneric(ctx, accessToken, confRealm, c.socialRealmName, userID, true, consentCode)
}

func (c *component) GetUser(ctx context.Context, realmName string, userID string, consentCode *string) (apikyc.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.getUserGeneric(ctx, accessToken, realmName, realmName, userID, false, consentCode)
}

func (c *component) getUserGeneric(ctx context.Context, accessToken string, confRealm string, targetRealm string, userID string, social bool, consentCode *string) (apikyc.UserRepresentation, error) {
	err := c.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, consentCode)
	if err != nil {
		return apikyc.UserRepresentation{}, err
	}

	kcUser, err := c.keycloakClient.GetUser(accessToken, targetRealm, userID)
	if err != nil {
		c.logger.Info(ctx, "msg", "GetUser: can't find user in Keycloak", "err", err.Error())
		return apikyc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	keycloakb.ConvertLegacyAttribute(&kcUser)

	profile, err := c.profileCache.GetRealmUserProfile(ctx, targetRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "failed to load user profile")
		return apikyc.UserRepresentation{}, err
	}

	var res apikyc.UserRepresentation
	res.ImportFromKeycloak(ctx, &kcUser, profile, c.logger)
	return res, nil
}

func (c *component) ValidateUser(ctx context.Context, realmName string, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.validateUser(ctx, accessToken, realmName, realmName, userID, user, consentCode)
}

func (c *component) ValidateUserInSocialRealm(ctx context.Context, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}

	var confRealm = ctx.Value(cs.CtContextRealm).(string)
	return c.validateUser(ctx, accessToken, confRealm, c.socialRealmName, userID, user, consentCode)
}

/********************* (BEGIN) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/
func (c *component) ValidateUserBasicID(ctx context.Context, userID string, user apikyc.UserRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}

	var confRealm = ctx.Value(cs.CtContextRealm).(string)
	return c.validateUserBasicID(ctx, accessToken, confRealm, c.socialRealmName, userID, user)
}

func (c *component) validateUserBasicID(ctx context.Context, accessToken string, confRealm string, targetRealm string, userID string, user apikyc.UserRepresentation) error {
	var operatorName = ctx.Value(cs.CtContextUsername).(string)

	// Get the user from Keycloak
	kcUser, err := c.keycloakClient.GetUser(accessToken, targetRealm, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "CreateAccreditations: can't get Keycloak user", "err", err.Error(), "realm", targetRealm, "user", userID)
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

	profile, err := c.profileCache.GetRealmUserProfile(ctx, targetRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "failed to load user profile")
		return err
	}

	user.ExportToKeycloak(&kcUser, profile)

	var now = time.Now()
	err = c.keycloakClient.UpdateUser(accessToken, targetRealm, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return err
	}

	// Notify the new check to accreditation service
	txnID := uuid.New().String()
	check := accreditationsclient.CheckRepresentation{
		UserID:    &userID,
		RealmName: &targetRealm,
		Operator:  &operatorName,
		DateTime:  &now,
		Status:    ptr("VERIFIED"),
		Type:      ptr("IDENTITY_CHECK"),
		Nature:    ptr("BASIC_CHECK"),
		Comment:   user.Comment,
		ProofType: nil,
		ProofData: nil,
		TxnID:     &txnID,
	}

	if user.Attachments != nil && len(*user.Attachments) == 1 {
		check.ProofType = (*user.Attachments)[0].ContentType
		check.ProofData = (*user.Attachments)[0].Content
	} else if user.Attachments != nil && len(*user.Attachments) > 1 {
		zipAttachments, err := c.zipAttachments(*user.Attachments)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Zip creation failed", "err", err.Error())
			return err
		}
		check.ProofType = ptr("application/zip")
		check.ProofData = &zipAttachments
	}

	err = c.accredsServiceClient.NotifyCheck(ctx, check)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Request to accreditations service to create a check failed", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "BASIC_VALIDATE_USER", targetRealm, userID, *user.Username, nil))

	var archiveUser = dto.ToArchiveUserRepresentation(kcUser)
	err = c.archiveDBModule.StoreUserDetails(ctx, targetRealm, archiveUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to archive user details", "err", err.Error())
	}

	return nil
}

/********************* (END) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/

func (c *component) validateUser(ctx context.Context, accessToken string, confRealm string, targetRealm string, userID string, user apikyc.UserRepresentation, consentCode *string) error {
	var operatorName = ctx.Value(cs.CtContextUsername).(string)

	var err = c.checkUserConsent(ctx, accessToken, confRealm, targetRealm, userID, consentCode)
	if err != nil {
		return err
	}

	// Gets user from Keycloak
	var kcUser kc.UserRepresentation
	kcUser, err = c.keycloakClient.GetUser(accessToken, targetRealm, userID)
	if err != nil {
		var httpErr kc.HTTPError
		if errors.As(err, &httpErr) && httpErr.HTTPStatus == 404 {
			c.logger.Info(ctx, "msg", "User does not exist", "userID", userID)
			return errorhandler.CreateNotFoundError("user")
		}
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

	profile, err := c.profileCache.GetRealmUserProfile(ctx, targetRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "failed to load user profile")
		return err
	}

	user.ExportToKeycloak(&kcUser, profile)

	var now = time.Now()
	err = c.keycloakClient.UpdateUser(accessToken, targetRealm, userID, kcUser)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to update user through Keycloak API", "err", err.Error())
		return err
	}

	// Notify the new check to accreditation service
	txnID := uuid.New().String()
	check := accreditationsclient.CheckRepresentation{
		UserID:    &userID,
		RealmName: &targetRealm,
		Operator:  &operatorName,
		DateTime:  &now,
		Status:    ptr("VERIFIED"),
		Type:      ptr("IDENTITY_CHECK"),
		Nature:    ptr("PHYSICAL_CHECK"),
		Comment:   user.Comment,
		ProofType: nil,
		ProofData: nil,
		TxnID:     &txnID,
	}

	if user.Attachments != nil && len(*user.Attachments) == 1 {
		check.ProofType = (*user.Attachments)[0].ContentType
		check.ProofData = (*user.Attachments)[0].Content
	} else if user.Attachments != nil && len(*user.Attachments) > 1 {
		zipAttachments, err := c.zipAttachments(*user.Attachments)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Zip creation failed", "err", err.Error())
			return err
		}
		check.ProofType = ptr("application/zip")
		check.ProofData = &zipAttachments
	}

	err = c.accredsServiceClient.NotifyCheck(ctx, check)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Request to accreditations service to create a check failed", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "VALIDATE_USER", targetRealm, userID, *user.Username, nil))

	var archiveUser = dto.ToArchiveUserRepresentation(kcUser)
	err = c.archiveDBModule.StoreUserDetails(ctx, targetRealm, archiveUser)
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

func (c *component) getUserByUsername(accessToken, reqRealmName, targetRealmName, username string, groupID *string) (kc.UserRepresentation, error) {
	var params = []string{"username", username}
	if groupID != nil {
		params = append(params, "groupId", *groupID)
	}

	var kcUsers, err = c.keycloakClient.GetUsers(accessToken, reqRealmName, targetRealmName, params...)
	if err != nil {
		return kc.UserRepresentation{}, errorhandler.CreateInternalServerError("keycloak")
	}
	if kcUsers.Count == nil || *kcUsers.Count != 1 || kcUsers.Users[0].Username == nil || !strings.EqualFold(*kcUsers.Users[0].Username, username) {
		return kc.UserRepresentation{}, errorhandler.CreateNotFoundError("user")
	}

	var res = kcUsers.Users[0]
	keycloakb.ConvertLegacyAttribute(&res)
	return res, nil
}

func ptr(value string) *string {
	return &value
}

func (c *component) SendSmsConsentCodeInSocialRealm(ctx context.Context, userID string) error {
	var accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return err
	}
	var confRealm = ctx.Value(cs.CtContextRealm).(string)
	return c.sendSmsConsentCodeGeneric(ctx, accessToken, confRealm, c.socialRealmName, userID)
}

func (c *component) SendSmsConsentCode(ctx context.Context, realmName string, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.sendSmsConsentCodeGeneric(ctx, accessToken, realmName, realmName, userID)
}

func (c *component) sendSmsConsentCodeGeneric(ctx context.Context, accessToken string, confRealm, targetRealm string, userID string) error {
	if rac, err := c.configDBModule.GetAdminConfiguration(ctx, confRealm); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm admin configuration", "realm", confRealm, "err", err.Error())
		return err
	} else if !c.consentRequired(rac, targetRealm) {
		c.logger.Warn(ctx, "msg", "Consent feature is not activated for this realm", "realm", confRealm)
		return errorhandler.CreateEndpointNotEnabled("consent")
	}

	var err = c.keycloakClient.SendConsentCodeSMS(accessToken, targetRealm, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't send consent SMS", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SMS_CONSENT", targetRealm, userID, events.CtEventUnknownUsername, nil))

	return nil
}

func (c *component) SendSmsCodeInSocialRealm(ctx context.Context, userID string) (string, error) {
	var accessToken, err = c.tokenProvider.ProvideTokenForRealm(ctx, c.socialRealmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return "", err
	}

	return c.sendSmsCodeGeneric(ctx, accessToken, c.socialRealmName, userID)
}

func (c *component) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	return c.sendSmsCodeGeneric(ctx, accessToken, realmName, userID)
}

func (c *component) sendSmsCodeGeneric(ctx context.Context, accessToken string, realm string, userID string) (string, error) {
	smsCodeKc, err := c.keycloakClient.SendSmsCode(accessToken, realm, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	// store the API call into the DB
	c.auditEventsReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SMS_CHALLENGE", realm, userID, events.CtEventUnknownUsername, nil))

	return *smsCodeKc.Code, err
}

func (c *component) zipAttachments(attachments []apikyc.AttachmentRepresentation) ([]byte, error) {
	buf := new(bytes.Buffer)

	w := zip.NewWriter(buf)

	for _, attachment := range attachments {
		f, err := w.Create(*attachment.Filename)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(*attachment.Content)
		if err != nil {
			return nil, err
		}
	}

	err := w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
