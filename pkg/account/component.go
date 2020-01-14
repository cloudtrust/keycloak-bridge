package account

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
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
	GetConfiguration(context.Context) (api.Configuration, error)
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	NewTransaction(context context.Context) (database.Transaction, error)
	StoreOrUpdate(context.Context, string, dto.RealmConfiguration) error
	GetConfiguration(context.Context, string) (dto.RealmConfiguration, error)
	GetAuthorizations(context context.Context, realmID string, groupID string) ([]dto.Authorization, error)
	CreateAuthorization(context context.Context, authz dto.Authorization) error
	DeleteAuthorizations(context context.Context, realmID string, groupID string) error
	DeleteAuthorizationsWithGroupID(context context.Context, groupID string) error
}

// Component is the management component.
type component struct {
	keycloakAccountClient KeycloakAccountClient
	eventDBModule         database.EventsDBModule
	configDBModule        ConfigurationDBModule
	logger                internal.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, eventDBModule database.EventsDBModule, configDBModule ConfigurationDBModule, logger internal.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		eventDBModule:         eventDBModule,
		configDBModule:        configDBModule,
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

	var userRep api.AccountRepresentation
	userKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return userRep, err
	}

	userRep = api.ConvertToAPIAccount(userKc)

	return userRep, nil
}

func (c *component) UpdateAccount(ctx context.Context, user api.AccountRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)
	var userRep kc.UserRepresentation

	// get the "old" user representation
	oldUserKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm)
	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	var emailVerified, phoneNumberVerified *bool

	// when the email changes, set the EmailVerified to false
	if user.Email != nil && oldUserKc.Email != nil && *oldUserKc.Email != *user.Email {
		var verified = false
		emailVerified = &verified
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if user.PhoneNumber != nil {
		if oldUserKc.Attributes != nil {
			var m = *oldUserKc.Attributes
			if _, ok := m["phoneNumber"]; !ok || m["phoneNumber"][0] != *user.PhoneNumber {
				var verified = false
				phoneNumberVerified = &verified
			}
		} else { // the user has no attributes until now, i.e. he has not set yet his phone number
			var verified = false
			phoneNumberVerified = &verified
		}
	}

	userRep = api.ConvertToKCUser(user)

	if emailVerified != nil {
		userRep.EmailVerified = emailVerified
	}

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = make(map[string][]string)

	//Populate with the old attributes
	if oldUserKc.Attributes != nil {
		for key, attribute := range *oldUserKc.Attributes {
			mergedAttributes[key] = attribute
		}
	}

	if user.PhoneNumber != nil {
		mergedAttributes["phoneNumber"] = []string{*user.PhoneNumber}
	}

	if phoneNumberVerified != nil {
		mergedAttributes["phoneNumberVerified"] = []string{strconv.FormatBool(*phoneNumberVerified)}
	}

	userRep.Attributes = &mergedAttributes

	err = c.keycloakAccountClient.UpdateAccount(accessToken, realm, userRep)

	if err != nil {
		c.logger.Warn(ctx, "err", err.Error())
		return err
	}

	//store the API call into the DB
	c.reportEvent(ctx, "UPDATE_ACCOUNT", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	return nil
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
	additionalInfos, _ := json.Marshal(map[string]string{"credentialID": credentialID, "label": label})

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

	additionalInfos, _ := json.Marshal(map[string]string{"credentialID": credentialID})

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

	additionalInfos, err := json.Marshal(map[string]string{"credentialID": credentialID, "previousCredentialID": previousCredentialID})

	//store the API call into the DB
	c.reportEvent(ctx, "SELF_MOVE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

	return nil
}

func (c *component) GetConfiguration(ctx context.Context) (api.Configuration, error) {
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	config, err := c.configDBModule.GetConfiguration(ctx, currentRealm)
	if err != nil {
		return api.Configuration{}, err
	}

	return api.Configuration{
		ShowAuthenticatorsTab:     config.ShowAuthenticatorsTab,
		ShowAccountDeletionButton: config.ShowAccountDeletionButton,
		ShowMailEditing:           config.ShowMailEditing,
		ShowPasswordTab:           config.ShowPasswordTab,
	}, nil
}
