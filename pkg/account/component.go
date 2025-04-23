package account

import (
	"context"
	"net/http"
	"strings"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/events"
	"github.com/cloudtrust/common-service/v2/fields"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// Constants
const (
	ActionVerifyEmail       = "ct-verify-email"
	ActionVerifyPhoneNumber = "mobilephone-validation"

	emailTemplateUpdatedPassword = "notif-password-change.ftl"
	emailSubjectUpdatedPassword  = "notifPasswordChangeSubject"
	emailTemplateUpdatedEmail    = "notif-email-change.ftl"
	emailSubjectUpdatedEmail     = "notifEmailChangeSubject"
	emailTemplateUpdatedProfile  = "notif-profile-change.ftl"
	emailSubjectUpdatedProfile   = "notifProfileChangeSubject"

	eventCredentialID     = "credential_id"
	eventPrevCredentialID = "previous_credential_id"
)

// KeycloakAccountClient interface exposes methods we need to call to send requests to Keycloak API of Account
type KeycloakAccountClient interface {
	UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword string) (string, error)
	GetCredentials(accessToken string, realmName string) ([]kc.CredentialRepresentation, error)
	GetCredentialRegistrators(accessToken string, realmName string) ([]string, error)
	UpdateLabelCredential(accessToken string, realmName string, credentialID string, label string) error
	DeleteCredential(accessToken string, realmName string, credentialID string) error
	MoveToFirst(accessToken string, realmName string, credentialID string) error
	MoveAfter(accessToken string, realmName string, credentialID string, previousCredentialID string) error
	UpdateAccount(accessToken, realm string, user kc.UserRepresentation) error
	GetAccount(accessToken, realm string) (kc.UserRepresentation, error)
	DeleteAccount(accessToken, realm string) error
	ExecuteActionsEmail(accessToken string, realmName string, actions []string) error
	SendEmail(accessToken, realmName, template, subject string, recipient *string, attributes map[string]string) error
}

// KeycloakTechnicalClient interface exposes methods called by a technical account
type KeycloakTechnicalClient interface {
	GetRealm(ctx context.Context, realmName string) (kc.RealmRepresentation, error)
	GetUsers(ctx context.Context, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	LogoutAllSessions(ctx context.Context, realmName string, userID string) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
	GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error)
	GetCredentialRegistrators(ctx context.Context) ([]string, error)
	UpdateLabelCredential(ctx context.Context, credentialID string, label string) error
	DeleteCredential(ctx context.Context, credentialID string) error
	MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error
	GetAccount(ctx context.Context) (api.AccountRepresentation, error)
	UpdateAccount(context.Context, api.UpdatableAccountRepresentation) error
	DeleteAccount(context.Context) error
	GetConfiguration(context.Context, string) (api.Configuration, error)
	GetUserProfile(context.Context) (apicommon.ProfileRepresentation, error)
	SendVerifyEmail(ctx context.Context) error
	SendVerifyPhoneNumber(ctx context.Context) error
	CancelEmailChange(ctx context.Context) error
	CancelPhoneNumberChange(ctx context.Context) error
}

// UserProfileCache interface
type UserProfileCache interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// AccreditationsServiceClient interface
type AccreditationsServiceClient interface {
	GetChecks(ctx context.Context, realm string, userID string) ([]accreditationsclient.CheckRepresentation, error)
	GetPendingChecks(ctx context.Context, realm string, userID string) ([]accreditationsclient.CheckRepresentation, error)
	NotifyUpdate(ctx context.Context, updateNotifyRequest accreditationsclient.UpdateNotificationRepresentation) ([]string, error)
}

// EventsReporterModule interface
type EventsReporterModule interface {
	ReportEvent(ctx context.Context, event events.Event)
}

// Component is the management component.
type component struct {
	keycloakAccountClient KeycloakAccountClient
	keycloakTechClient    KeycloakTechnicalClient
	profileCache          UserProfileCache
	eventReporterModule   EventsReporterModule
	configDBModule        keycloakb.ConfigurationDBModule
	accreditationsClient  AccreditationsServiceClient
	logger                log.Logger
	originEvent           string
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, keycloakTechClient KeycloakTechnicalClient, profileCache UserProfileCache, eventReporterModule EventsReporterModule,
	configDBModule keycloakb.ConfigurationDBModule, accreditationsClient AccreditationsServiceClient, logger log.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		keycloakTechClient:    keycloakTechClient,
		profileCache:          profileCache,
		eventReporterModule:   eventReporterModule,
		configDBModule:        configDBModule,
		accreditationsClient:  accreditationsClient,
		logger:                logger,
		originEvent:           "self-service",
	}
}

func (c *component) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	if currentPassword == newPassword || newPassword != confirmPassword {
		return errorhandler.Error{
			Status:  http.StatusBadRequest,
			Message: keycloakb.ComponentName + "." + "invalidValues",
		}
	}

	_, err := c.keycloakAccountClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update password", "err", err.Error())
		return err
	}

	// account.update.password should be "trustID: Security Alert"
	var attributes = make(map[string]string)
	if c.sendEmail(ctx, emailTemplateUpdatedPassword, emailSubjectUpdatedPassword, nil, attributes) == nil {
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "UPDATED_PWD_EMAIL_SENT", realm, userID, username, nil))
	}

	//store the API call into the DB
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "PASSWORD_RESET", realm, userID, username, nil))

	if err = c.keycloakTechClient.LogoutAllSessions(ctx, realm, userID); err != nil {
		c.logger.Warn(ctx, "msg", "User updated his/her password but logout of sessions failed", "err", err.Error(), "realm", realm, "user", userID)
	}

	return nil
}

func (c *component) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)

	var userRep api.AccountRepresentation
	userKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get account", "err", err.Error())
		return userRep, err
	}
	keycloakb.ConvertLegacyAttribute(&userKc)

	pendingChecks, err := c.accreditationsClient.GetPendingChecks(ctx, realm, userID)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get pending checks", "err", err.Error())
		return userRep, err
	}

	userRep = api.ConvertToAPIAccount(ctx, userKc, c.logger)
	userRep.PendingChecks = keycloakb.ConvertFromAccreditationChecks(pendingChecks).ToCheckNames()

	return userRep, nil
}

func isEmailVerified(user kc.UserRepresentation) bool {
	return user.EmailVerified != nil && *user.EmailVerified
}

func isPhoneNumberVerified(user kc.UserRepresentation) bool {
	var value, err = user.GetAttributeBool(constants.AttrbPhoneNumberVerified)
	return err == nil && value != nil && *value
}

// UpdateAccount updates an user account
func (c *component) UpdateAccount(ctx context.Context, user api.UpdatableAccountRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	// get the "old" user representation from Keycloak
	oldUserKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get account", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&oldUserKc)

	var actions []string

	var fieldsComparator = fields.NewFieldsComparator().
		CompareValueAndFunctionForUpdate(fields.Email, user.Email, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.FirstName, user.FirstName, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.LastName, user.LastName, oldUserKc.GetFieldValues).
		CompareOptionalAndFunction(fields.BusinessID, user.BusinessID, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.Gender, user.Gender, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.PhoneNumber, user.PhoneNumber, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.BirthDate, user.BirthDate, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.BirthLocation, user.BirthLocation, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.Nationality, user.Nationality, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentType, user.IDDocumentType, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentNumber, user.IDDocumentNumber, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentExpiration, user.IDDocumentExpiration, oldUserKc.GetFieldValues).
		CompareValueAndFunctionForUpdate(fields.IDDocumentCountry, user.IDDocumentCountry, oldUserKc.GetFieldValues)

	var updateRequest = accreditationsclient.UpdateNotificationRepresentation{
		UserID:        &userID,
		RealmName:     &realm,
		UpdatedFields: fieldsComparator.UpdatedFields(),
	}
	revokeAccreds, err := c.accreditationsClient.NotifyUpdate(ctx, updateRequest)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to notify accreditation service", "err", err.Error())
		return err
	}
	var ap, _ = keycloakb.NewAccreditationsProcessor(oldUserKc.GetFieldValues(fields.Accreditations))
	var revokedAccreditations []keycloakb.AccreditationRepresentation
	ap.RevokeTypes(revokeAccreds, func(accred keycloakb.AccreditationRepresentation) {
		revokedAccreditations = append(revokedAccreditations, accred)
	})
	newAccreditations := ap.ToKeycloak()

	oldUserKc.SetFieldValues(fields.Accreditations, newAccreditations)

	// profileChangesCount count the change in the profile without taking the email into account
	var profileChangesCount = len(fieldsComparator.UpdatedFields())

	// manage email change
	var prevEmail *string
	if fieldsComparator.IsFieldUpdated(fields.Email) {
		actions = append(actions, ActionVerifyEmail)
		if isEmailVerified(oldUserKc) {
			oldUserKc.SetAttributeString(constants.AttrbEmailToValidate, *user.Email)
			prevEmail = oldUserKc.Email
			profileChangesCount--
		} else {
			oldUserKc.Email = user.Email
			oldUserKc.RemoveAttribute(constants.AttrbEmailToValidate)
			prevEmail = nil
			profileChangesCount = 0 // Mail won't be sent to unverified current email
		}
	}

	// manage phone number change
	if fieldsComparator.IsFieldUpdated(fields.PhoneNumber) {
		actions = append(actions, ActionVerifyPhoneNumber)
		if isPhoneNumberVerified(oldUserKc) {
			oldUserKc.SetAttributeString(constants.AttrbPhoneNumberToValidate, *user.PhoneNumber)
		} else {
			oldUserKc.SetAttributeString(constants.AttrbPhoneNumber, *user.PhoneNumber)
			oldUserKc.RemoveAttribute(constants.AttrbPhoneNumberToValidate)
		}
	}

	api.MergeUserWithoutEmailAndPhoneNumber(&oldUserKc, user)
	if len(newAccreditations) > 0 {
		oldUserKc.SetFieldValues(fields.Accreditations, newAccreditations)
	}

	// Update keycloak account
	err = c.keycloakAccountClient.UpdateAccount(accessToken, realm, oldUserKc)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update account", "err", err.Error())
		return err
	}

	// store the API call into the DB - As user is partially update, report event even if database update fails
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "UPDATE_ACCOUNT", realm, userID, username, nil))
	for _, accred := range revokedAccreditations {
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "ACCREDITATION_REVOKED", realm, userID, username, accred.ToDetails()))
	}

	if len(actions) > 0 {
		err = c.executeActions(ctx, actions)
		// Error occured but account is updated and event reported... should we return an error here ?
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't execute actions", "err", err.Error())
			return err
		}
	}

	var attributes = make(map[string]string)
	if prevEmail != nil && c.sendEmail(ctx, emailTemplateUpdatedEmail, emailSubjectUpdatedEmail, prevEmail, attributes) == nil {
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "EMAIL_CHANGED_EMAIL_SENT", realm, userID, username, nil))
	}

	if profileChangesCount > 0 && isEmailVerified(oldUserKc) && c.sendEmail(ctx, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, attributes) == nil {
		c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "PROFILE_CHANGED_EMAIL_SENT", realm, userID, username, nil))
	}

	return err
}

func (c *component) sendEmail(ctx context.Context, template, subject string, recipient *string, attributes map[string]string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	if emailErr := c.keycloakAccountClient.SendEmail(accessToken, realm, template, subject, recipient, attributes); emailErr != nil {
		c.logger.Warn(ctx, "msg", "Could not send email", "err", emailErr.Error(), "template", template)
		return emailErr
	}
	return nil
}

func (c *component) DeleteAccount(ctx context.Context) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	err := c.keycloakAccountClient.DeleteAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete account", "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SELF_DELETE_ACCOUNT", realm, userID, username, nil))

	return nil
}

func (c *component) GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	credentialsKc, err := c.keycloakAccountClient.GetCredentials(accessToken, currentRealm)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get credentials", "err", err.Error())
		return nil, err
	}

	var credentialsRep = []api.CredentialRepresentation{}
	for _, credentialKc := range credentialsKc {
		var credentialRep = api.ConvertCredential(&credentialKc)
		credentialsRep = append(credentialsRep, credentialRep)
	}

	return credentialsRep, err
}

func (c *component) GetCredentialRegistrators(ctx context.Context) ([]string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	credentialTypes, err := c.keycloakAccountClient.GetCredentialRegistrators(accessToken, currentRealm)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get credential registrators", "err", err.Error())
		return nil, err
	}

	return credentialTypes, nil
}

func (c *component) UpdateLabelCredential(ctx context.Context, credentialID string, label string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	err := c.keycloakAccountClient.UpdateLabelCredential(accessToken, currentRealm, credentialID, label)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update credential label", "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SELF_UPDATE_CREDENTIAL", currentRealm, userID, username, map[string]string{eventCredentialID: credentialID, "label": label}))

	return nil
}

func (c *component) DeleteCredential(ctx context.Context, credentialID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	var fnGetCredentials = func() ([]kc.CredentialRepresentation, error) {
		return c.keycloakAccountClient.GetCredentials(accessToken, currentRealm)
	}

	if err := keycloakb.CheckRemovableMFA(ctx, credentialID, false, fnGetCredentials, c.logger); err != nil {
		return err
	}

	if err := c.keycloakAccountClient.DeleteCredential(accessToken, currentRealm, credentialID); err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete credential", "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SELF_DELETE_CREDENTIAL", currentRealm, userID, username, map[string]string{eventCredentialID: credentialID}))

	return nil
}

func (c *component) MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var err error

	if previousCredentialID == "null" {
		err = c.keycloakAccountClient.MoveToFirst(accessToken, currentRealm, credentialID)
	} else {
		err = c.keycloakAccountClient.MoveAfter(accessToken, currentRealm, credentialID, previousCredentialID)
	}

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't move credential", "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "SELF_MOVE_CREDENTIAL", currentRealm, userID, username, map[string]string{eventCredentialID: credentialID, eventPrevCredentialID: previousCredentialID}))

	return nil
}

func (c *component) GetConfiguration(ctx context.Context, realmIDOverride string) (api.Configuration, error) {
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	config, err := c.configDBModule.GetConfiguration(ctx, currentRealm)
	if err != nil {
		return api.Configuration{}, err
	}

	var adminConfig configuration.RealmAdminConfiguration
	adminConfig, err = c.configDBModule.GetAdminConfiguration(ctx, currentRealm)
	if err != nil {
		return api.Configuration{}, err
	}

	var realmConf kc.RealmRepresentation
	if realmConf, err = c.keycloakTechClient.GetRealm(ctx, currentRealm); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get Keycloak realm configuration", "err", err.Error(), "realm", currentRealm)
		return api.Configuration{}, err
	}

	var supportedLocales *[]string
	if realmConf.InternationalizationEnabled != nil && *realmConf.InternationalizationEnabled {
		supportedLocales = realmConf.SupportedLocales
	}

	allowedBackURLs := []string{}
	if config.AllowedBackURL != nil {
		allowedBackURLs = []string{*config.AllowedBackURL}
	} else if config.AllowedBackURLs != nil {
		allowedBackURLs = config.AllowedBackURLs
	}

	var apiConfig = api.Configuration{
		EditingEnabled:                        config.APISelfAccountEditingEnabled,
		ShowAuthenticatorsTab:                 config.ShowAuthenticatorsTab,
		ShowAccountDeletionButton:             config.ShowAccountDeletionButton,
		ShowPasswordTab:                       config.ShowPasswordTab,
		ShowProfileTab:                        config.ShowProfileTab,
		SelfServiceDefaultTab:                 config.SelfServiceDefaultTab,
		RedirectSuccessfulRegistrationURL:     config.RedirectSuccessfulRegistrationURL,
		BarcodeType:                           config.BarcodeType,
		AvailableChecks:                       adminConfig.AvailableChecks,
		Theme:                                 adminConfig.SseTheme,
		SupportedLocales:                      supportedLocales,
		ShowGlnEditing:                        adminConfig.ShowGlnEditing,
		VideoIdentificationVoucherEnabled:     adminConfig.VideoIdentificationVoucherEnabled,
		VideoIdentificationAccountingEnabled:  adminConfig.VideoIdentificationAccountingEnabled,
		VideoIdentificationPrepaymentRequired: adminConfig.VideoIdentificationPrepaymentRequired,
		AutoIdentificationVoucherEnabled:      adminConfig.AutoIdentificationVoucherEnabled,
		AutoIdentificationAccountingEnabled:   adminConfig.AutoIdentificationAccountingEnabled,
		AutoIdentificationPrepaymentRequired:  adminConfig.AutoIdentificationPrepaymentRequired,
		AllowedBackURLs:                       allowedBackURLs,
	}

	if realmIDOverride != "" {
		overrideConfig, err := c.configDBModule.GetConfiguration(ctx, realmIDOverride)
		if err != nil {
			return api.Configuration{}, err
		}

		apiConfig.RedirectSuccessfulRegistrationURL = overrideConfig.RedirectSuccessfulRegistrationURL
		apiConfig.BarcodeType = overrideConfig.BarcodeType
	}

	return apiConfig, nil
}

func (c *component) GetUserProfile(ctx context.Context) (apicommon.ProfileRepresentation, error) {
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var profile, err = c.profileCache.GetRealmUserProfile(ctx, currentRealm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get users profile", "err", err.Error())
		return apicommon.ProfileRepresentation{}, err
	}

	return apicommon.ProfileToAPI(profile, apiName), nil
}

func (c *component) SendVerifyEmail(ctx context.Context) error {
	return c.executeActions(ctx, []string{ActionVerifyEmail})
}

func (c *component) SendVerifyPhoneNumber(ctx context.Context) error {
	return c.executeActions(ctx, []string{ActionVerifyPhoneNumber})
}

func (c *component) executeActions(ctx context.Context, actions []string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var err = c.keycloakAccountClient.ExecuteActionsEmail(accessToken, currentRealm, actions)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't execute actions email", "err", err.Error())
		return err
	}

	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "ACTION_EMAIL", currentRealm, userID, username, map[string]string{"actions": strings.Join(actions, ",")}))

	return err
}

func (c *component) CancelEmailChange(ctx context.Context) error {
	return c.removeAttributeFromUser(ctx, constants.AttrbEmailToValidate)
}

func (c *component) CancelPhoneNumberChange(ctx context.Context) error {
	return c.removeAttributeFromUser(ctx, constants.AttrbPhoneNumberToValidate)
}

func (c *component) removeAttributeFromUser(ctx context.Context, attr kc.AttributeKey) error {
	accessToken := ctx.Value(cs.CtContextAccessToken).(string)
	realm := ctx.Value(cs.CtContextRealm).(string)

	// Get the user representation from Keycloak
	userKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get account", "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&userKc)

	if userKc.GetAttributeString(attr) == nil {
		// Attribute is already missing, no reason to update the user
		return nil
	}

	userKc.RemoveAttribute(attr)

	// Update keycloak account
	err = c.keycloakAccountClient.UpdateAccount(accessToken, realm, userKc)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update account", "err", err.Error())
		return err
	}

	userID := ctx.Value(cs.CtContextUserID).(string)
	username := ctx.Value(cs.CtContextUsername).(string)
	c.eventReporterModule.ReportEvent(ctx, events.NewEventOnUserFromContext(ctx, c.logger, c.originEvent, "UPDATE_ACCOUNT", realm, userID, username, nil))

	return nil
}
