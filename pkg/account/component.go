package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/fields"
	csjson "github.com/cloudtrust/common-service/v2/json"
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

// GlnVerifier interface allows to check validity of a GLN
type GlnVerifier interface {
	ValidateGLN(firstName, lastName, gln string) error
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

// Component is the management component.
type component struct {
	keycloakAccountClient KeycloakAccountClient
	keycloakTechClient    KeycloakTechnicalClient
	profileCache          UserProfileCache
	eventDBModule         database.EventsDBModule
	configDBModule        keycloakb.ConfigurationDBModule
	glnVerifier           GlnVerifier
	accreditationsClient  AccreditationsServiceClient
	logger                keycloakb.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, keycloakTechClient KeycloakTechnicalClient, profileCache UserProfileCache, eventDBModule database.EventsDBModule,
	configDBModule keycloakb.ConfigurationDBModule, glnVerifier GlnVerifier, accreditationsClient AccreditationsServiceClient, logger keycloakb.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		keycloakTechClient:    keycloakTechClient,
		profileCache:          profileCache,
		eventDBModule:         eventDBModule,
		configDBModule:        configDBModule,
		glnVerifier:           glnVerifier,
		accreditationsClient:  accreditationsClient,
		logger:                logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventDBModule.ReportEvent(ctx, apiCall, "self-service", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		keycloakb.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
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
		c.reportEvent(ctx, "UPDATED_PWD_EMAIL_SENT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)
	}

	//store the API call into the DB
	c.reportEvent(ctx, "PASSWORD_RESET", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

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

func defaultString(value1, value2 *string) *string {
	if value1 != nil {
		return value1
	}
	return value2
}

func (c *component) UpdateAccount(ctx context.Context, user api.UpdatableAccountRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var userRep kc.UserRepresentation

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
	ap.RevokeTypes(revokeAccreds)
	newAccreditations := ap.ToKeycloak()

	oldUserKc.SetFieldValues(fields.Accreditations, newAccreditations)

	// profileChangesCount count the change in the profile without taking the email into account
	var profileChangesCount = len(fieldsComparator.UpdatedFields())

	// manage email change
	var prevEmail *string
	if fieldsComparator.IsFieldUpdated(fields.Email) {
		prevEmail = oldUserKc.Email
		oldUserKc.SetAttributeString(constants.AttrbEmailToValidate, *user.Email)
		actions = append(actions, ActionVerifyEmail)
		profileChangesCount--
	}

	// manage phone number change
	if fieldsComparator.IsFieldUpdated(fields.PhoneNumber) {
		oldUserKc.SetAttributeString(constants.AttrbPhoneNumberToValidate, *user.PhoneNumber)
		actions = append(actions, ActionVerifyPhoneNumber)
	}

	userRep = api.ConvertToKCUser(user)

	userRep.FirstName = defaultString(userRep.FirstName, oldUserKc.FirstName)
	userRep.LastName = defaultString(userRep.LastName, oldUserKc.LastName)
	userRep.Email = oldUserKc.Email // Don't touch email
	userRep.EmailVerified = oldUserKc.EmailVerified

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = c.duplicateAttributes(oldUserKc.Attributes)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	mergedAttributes.SetDateWhenNotNil(constants.AttrbBirthDate, user.BirthDate, constants.SupportedDateLayouts)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbBusinessID, user.BusinessID.Value)
	if user.BusinessID.Defined && user.BusinessID.Value == nil {
		mergedAttributes.Remove(constants.AttrbBusinessID)
	}
	mergedAttributes.SetStringWhenNotNil(constants.AttrbBirthLocation, user.BirthLocation)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbNationality, user.Nationality)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, user.IDDocumentType)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, user.IDDocumentNumber)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, user.IDDocumentExpiration)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, user.IDDocumentCountry)

	userRep.Attributes = &mergedAttributes
	if len(newAccreditations) > 0 {
		userRep.SetFieldValues(fields.Accreditations, newAccreditations)
	}

	// GLN check
	if err = c.checkGLN(ctx, user.BusinessID, &userRep); err != nil {
		return err
	}
	// Update keycloak account
	err = c.keycloakAccountClient.UpdateAccount(accessToken, realm, userRep)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't update account", "err", err.Error())
		return err
	}

	// store the API call into the DB
	c.reportEvent(ctx, "UPDATE_ACCOUNT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

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
		c.reportEvent(ctx, "EMAIL_CHANGED_EMAIL_SENT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)
	}
	if profileChangesCount > 0 && c.sendEmail(ctx, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, attributes) == nil {
		c.reportEvent(ctx, "PROFILE_CHANGED_EMAIL_SENT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)
	}

	return err
}

func (c *component) checkGLN(ctx context.Context, businessID csjson.OptionalString, kcUser *kc.UserRepresentation) error {
	var realm = ctx.Value(cs.CtContextRealm).(string)

	if adminConfig, err := c.configDBModule.GetAdminConfiguration(ctx, realm); err != nil {
		c.logger.Warn(ctx, "msg", "Can't get realm admin configuration", "realm", realm, "err", err.Error())
		return err
	} else if adminConfig.ShowGlnEditing == nil || !*adminConfig.ShowGlnEditing {
		// No GLN expected
		kcUser.RemoveAttribute(constants.AttrbBusinessID)
	} else if businessID.Defined {
		// GLN enabled for this realm
		if businessID.Value == nil {
			kcUser.RemoveAttribute(constants.AttrbBusinessID)
		} else {
			return c.glnVerifier.ValidateGLN(*kcUser.FirstName, *kcUser.LastName, *businessID.Value)
		}
	}
	return nil
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

func (c *component) duplicateAttributes(srcAttributes *kc.Attributes) kc.Attributes {
	var copiedAttributes = make(kc.Attributes)
	//Populate with the old attributes
	if srcAttributes != nil {
		for key, attribute := range *srcAttributes {
			copiedAttributes[key] = attribute
		}
	}
	return copiedAttributes
}

func (c *component) DeleteAccount(ctx context.Context) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)

	err := c.keycloakAccountClient.DeleteAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete account", "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.reportEvent(ctx, "SELF_DELETE_ACCOUNT", database.CtEventRealmName, realm)

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
	// the error should be treated
	additionalInfos, _ := json.Marshal(map[string]string{PrmCredentialID: credentialID, "label": label})

	c.reportEvent(ctx, "SELF_UPDATE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

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

	additionalInfos, _ := json.Marshal(map[string]string{PrmCredentialID: credentialID})

	//store the API call into the DB
	c.reportEvent(ctx, "SELF_DELETE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

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

	additionalInfos, _ := json.Marshal(map[string]string{PrmCredentialID: credentialID, PrmPrevCredentialID: previousCredentialID})

	//store the API call into the DB
	c.reportEvent(ctx, "SELF_MOVE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

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
		AllowedBackURL:                        config.AllowedBackURL,
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
	var err = c.keycloakAccountClient.ExecuteActionsEmail(accessToken, currentRealm, actions)

	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't execute actions email", "err", err.Error())
		return err
	}

	var additionalInfos = map[string]string{"actions": strings.Join(actions, ",")}
	var additionalBytes, _ = json.Marshal(additionalInfos)
	var additionalString = string(additionalBytes)
	c.reportEvent(ctx, "ACTION_EMAIL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventAdditionalInfo, additionalString)

	return err
}
