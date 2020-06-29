package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cloudtrust/common-service/configuration"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// Constants
const (
	ActionVerifyEmail       = "VERIFY_EMAIL"
	ActionVerifyPhoneNumber = "mobilephone-validation"
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
	UpdateAccount(context.Context, api.AccountRepresentation) error
	DeleteAccount(context.Context) error
	GetConfiguration(context.Context, string) (api.Configuration, error)
	SendVerifyEmail(ctx context.Context) error
	SendVerifyPhoneNumber(ctx context.Context) error
}

// UsersDBModule is the minimum required interface to access the users database
type UsersDBModule interface {
	StoreOrUpdateUser(ctx context.Context, realm string, user dto.DBUser) error
	GetUser(ctx context.Context, realm string, userID string) (*dto.DBUser, error)
}

// Component is the management component.
type component struct {
	keycloakAccountClient KeycloakAccountClient
	eventDBModule         database.EventsDBModule
	configDBModule        keycloakb.ConfigurationDBModule
	usersDBModule         UsersDBModule
	logger                internal.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, eventDBModule database.EventsDBModule, configDBModule keycloakb.ConfigurationDBModule, usersDBModule UsersDBModule, logger internal.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		eventDBModule:         eventDBModule,
		configDBModule:        configDBModule,
		usersDBModule:         usersDBModule,
		logger:                logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := c.eventDBModule.ReportEvent(ctx, apiCall, "self-service", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		internal.LogUnrecordedEvent(ctx, c.logger, apiCall, errEvent.Error(), values...)
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
			Message: internal.ComponentName + "." + "invalidValues",
		}
	}

	_, err := c.keycloakAccountClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.reportEvent(ctx, "PASSWORD_RESET", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	return nil
}

func (c *component) GetAccount(ctx context.Context) (api.AccountRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)

	var userRep api.AccountRepresentation
	userKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return userRep, err
	}
	keycloakb.ConvertLegacyAttribute(&userKc)

	var dbUser *dto.DBUser
	dbUser, err = c.usersDBModule.GetUser(ctx, realm, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return userRep, err
	}

	userRep = api.ConvertToAPIAccount(ctx, userKc, c.logger)
	if dbUser != nil {
		userRep.BirthLocation = dbUser.BirthLocation
		userRep.IDDocumentType = dbUser.IDDocumentType
		userRep.IDDocumentNumber = dbUser.IDDocumentNumber
		userRep.IDDocumentExpiration = dbUser.IDDocumentExpiration
	}

	return userRep, nil
}

func isUpdated(newValue *string, oldValue *string) bool {
	return newValue != nil && (oldValue == nil || *newValue != *oldValue)
}

func (c *component) UpdateAccount(ctx context.Context, user api.AccountRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var userRep kc.UserRepresentation

	// get the "old" user representation from Keycloak
	oldUserKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}
	keycloakb.ConvertLegacyAttribute(&oldUserKc)

	// get the "old" user from DB
	var oldUser *dto.DBUser
	oldUser, err = c.usersDBModule.GetUser(ctx, realm, userID)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var emailVerified, phoneNumberVerified *bool
	var actions []string

	var revokeAccreditations = oldUser == nil || keycloakb.IsUpdated(user.FirstName, oldUserKc.FirstName,
		user.LastName, oldUserKc.LastName,
		user.Gender, oldUserKc.GetAttributeString(constants.AttrbGender),
		user.BirthDate, oldUserKc.GetAttributeString(constants.AttrbBirthDate),
		user.BirthLocation, oldUser.BirthLocation,
		user.IDDocumentType, oldUser.IDDocumentType,
		user.IDDocumentNumber, oldUser.IDDocumentNumber,
		user.IDDocumentExpiration, oldUser.IDDocumentExpiration,
	)

	// when the email changes, set the EmailVerified to false
	if isUpdated(user.Email, oldUserKc.Email) {
		var verified = false
		emailVerified = &verified
		actions = append(actions, ActionVerifyEmail)
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if isUpdated(user.PhoneNumber, oldUserKc.GetAttributeString(constants.AttrbPhoneNumber)) {
		var verified = false
		phoneNumberVerified = &verified
		actions = append(actions, ActionVerifyPhoneNumber)
	}

	userRep = api.ConvertToKCUser(user)

	if emailVerified != nil {
		userRep.EmailVerified = emailVerified
	}

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = c.duplicateAttributes(oldUserKc.Attributes)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbPhoneNumber, user.PhoneNumber)
	mergedAttributes.SetBoolWhenNotNil(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbGender, user.Gender)
	mergedAttributes.SetDateWhenNotNil(constants.AttrbBirthDate, user.BirthDate, constants.SupportedDateLayouts)
	mergedAttributes.SetStringWhenNotNil(constants.AttrbLocale, user.Locale)

	userRep.Attributes = &mergedAttributes
	if revokeAccreditations {
		keycloakb.RevokeAccreditations(&userRep)
	}

	err = c.keycloakAccountClient.UpdateAccount(accessToken, realm, userRep)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	// store the API call into the DB - As user is partially update, report event even if database update fails
	c.reportEvent(ctx, "UPDATE_ACCOUNT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	if len(actions) > 0 {
		err = c.executeActions(ctx, actions)
		// Error occured but account is updated and event reported... should we return an error here ?
		if err != nil {
			c.logger.Warn(ctx, "err", err.Error())
			return err
		}
	}

	var dbUser = c.mergeUser(userID, user, oldUser)

	err = c.usersDBModule.StoreOrUpdateUser(ctx, realm, dbUser)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
	}

	return err
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

func (c *component) mergeUser(userID string, user api.AccountRepresentation, oldUser *dto.DBUser) dto.DBUser {
	var dbUser = dto.DBUser{
		UserID:               &userID,
		BirthLocation:        user.BirthLocation,
		IDDocumentType:       user.IDDocumentType,
		IDDocumentNumber:     user.IDDocumentNumber,
		IDDocumentExpiration: user.IDDocumentExpiration,
	}
	if oldUser != nil {
		// Keep old values when none was provided
		if dbUser.BirthLocation == nil {
			dbUser.BirthLocation = oldUser.BirthLocation
		}
		if dbUser.IDDocumentType == nil {
			dbUser.IDDocumentType = oldUser.IDDocumentType
		}
		if dbUser.IDDocumentNumber == nil {
			dbUser.IDDocumentNumber = oldUser.IDDocumentNumber
		}
		if dbUser.IDDocumentExpiration == nil {
			dbUser.IDDocumentExpiration = oldUser.IDDocumentExpiration
		}
	}
	return dbUser
}

func (c *component) DeleteAccount(ctx context.Context) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)

	err := c.keycloakAccountClient.DeleteAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
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
		c.logger.Warn(ctx, "err", err.Error())
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
		c.logger.Warn(ctx, "err", err.Error())
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
		c.logger.Warn(ctx, "err", err.Error())
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

	err := c.keycloakAccountClient.DeleteCredential(accessToken, currentRealm, credentialID)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
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
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	additionalInfos, err := json.Marshal(map[string]string{PrmCredentialID: credentialID, PrmPrevCredentialID: previousCredentialID})

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

	var apiConfig = api.Configuration{
		EditingEnabled:                    config.APISelfAccountEditingEnabled,
		ShowAuthenticatorsTab:             config.ShowAuthenticatorsTab,
		ShowAccountDeletionButton:         config.ShowAccountDeletionButton,
		ShowPasswordTab:                   config.ShowPasswordTab,
		ShowProfileTab:                    config.ShowProfileTab,
		RedirectSuccessfulRegistrationURL: config.RedirectSuccessfulRegistrationURL,
		AvailableChecks:                   adminConfig.AvailableChecks,
		BarcodeType:                       config.BarcodeType,
	}

	if realmIDOverride != "" {
		overrideConfig, err := c.configDBModule.GetConfiguration(ctx, realmIDOverride)
		if err != nil {
			return api.Configuration{}, err
		}

		apiConfig.RedirectSuccessfulRegistrationURL = overrideConfig.RedirectSuccessfulRegistrationURL
	}

	return apiConfig, nil
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
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var additionalInfos = map[string]string{"actions": strings.Join(actions, ",")}
	var additionalBytes, _ = json.Marshal(additionalInfos)
	var additionalString = string(additionalBytes)
	c.reportEvent(ctx, "ACTION_EMAIL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventAdditionalInfo, additionalString)

	return err
}
