package account

import (
	"context"
	"encoding/json"
	"net/http"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	commonhttp "github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	apim "github.com/cloudtrust/keycloak-bridge/api/management"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakAccountClient interface exposes methods we need to call to send requests to Keycloak API of Account
type KeycloakAccountClient interface {
	UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword string) (string, error)
	GetCredentials(accessToken string, realmName string) ([]kc.CredentialRepresentation, error)
	GetCredentialTypes(accessToken string, realmName string) ([]string, error)
	UpdateLabelCredential(accessToken string, realmName string, credentialID string, label string) error
	DeleteCredential(accessToken string, realmName string, credentialID string) error
	MoveToFirst(accessToken string, realmName string, credentialID string) error
	MoveAfter(accessToken string, realmName string, credentialID string, previousCredentialID string) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
	GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error)
	GetCredentialTypes(ctx context.Context) ([]string, error)
	UpdateLabelCredential(ctx context.Context, credentialID string, label string) error
	DeleteCredential(ctx context.Context, credentialID string) error
	MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error
}

// Component is the management component.
type component struct {
	keycloakAccountClient KeycloakAccountClient
	eventDBModule         database.EventsDBModule
	configDBModule        internal.ConfigurationDBModule
	logger                internal.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, eventDBModule database.EventsDBModule, configDBModule internal.ConfigurationDBModule, logger internal.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		eventDBModule:         eventDBModule,
		configDBModule:        configDBModule,
		logger:                logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) error {
	return c.eventDBModule.ReportEvent(ctx, apiCall, "self-service", values...)
}

func (c *component) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	if currentPassword == newPassword || newPassword != confirmPassword {
		return commonhttp.Error{
			Status: http.StatusBadRequest,
		}
	}

	_, err := c.keycloakAccountClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)

	var updateError error
	if err != nil {
		switch err.Error() {
		case "invalidPasswordExistingMessage":
			updateError = commonhttp.Error{
				Status:  http.StatusBadRequest,
				Message: err.Error()}
		default:
			updateError = err
		}
	}

	//store the API call into the DB
	_ = c.reportEvent(ctx, "PASSWORD_RESET", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username)

	return updateError
}

func (c *component) GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	credentialsKc, err := c.keycloakAccountClient.GetCredentials(accessToken, currentRealm)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var credentialsRep = []api.CredentialRepresentation{}
	for _, credentialKc := range credentialsKc {
		var credentialRep = api.ConvertCredential(&credentialKc)
		credentialsRep = append(credentialsRep, credentialRep)
	}

	return credentialsRep, err
}

func (c *component) GetCredentialTypes(ctx context.Context) ([]string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)

	var customConfig apim.RealmCustomConfiguration
	{
		confJSON, err := c.configDBModule.GetConfiguration(ctx, currentRealm)
		if err == nil {
			if confJSON == "" {
				c.logger.Warn("err", "GetCredentialTypes called but realm is not configured", "realm", currentRealm)
				return []string{}, nil
			}
			err = json.Unmarshal([]byte(confJSON), &customConfig)
		}
		if err != nil {
			c.logger.Warn("err", err.Error())
			return nil, err
		}
	}

	credentialTypes, err := c.keycloakAccountClient.GetCredentialTypes(accessToken, currentRealm)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var pwdEnabled = customConfig.SelfPasswordChangeEnabled != nil && *customConfig.SelfPasswordChangeEnabled
	var otherEnabled = customConfig.SelfAuthenticatorMgmtEnabled != nil && *customConfig.SelfAuthenticatorMgmtEnabled

	res := []string{}
	for _, value := range credentialTypes {
		var isPassword = value == "password"
		if isPassword && pwdEnabled || !isPassword && otherEnabled {
			res = append(res, value)
		}
	}

	return res, nil
}

func (c *component) UpdateLabelCredential(ctx context.Context, credentialID string, label string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	err := c.keycloakAccountClient.UpdateLabelCredential(accessToken, currentRealm, credentialID, label)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB
	// the error should be treated
	additionalInfos, _ := json.Marshal(map[string]string{"credentialID": credentialID, "label": label})
	_ = c.reportEvent(ctx, "SELF_UPDATE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

	return nil
}

func (c *component) DeleteCredential(ctx context.Context, credentialID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var currentRealm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	err := c.keycloakAccountClient.DeleteCredential(accessToken, currentRealm, credentialID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB
	// the error should be treated
	additionalInfos, _ := json.Marshal(map[string]string{"credentialID": credentialID})
	_ = c.reportEvent(ctx, "SELF_DELETE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

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
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB
	// the error should be treated
	additionalInfos, _ := json.Marshal(map[string]string{"credentialID": credentialID, "previousCredentialID": previousCredentialID})
	_ = c.reportEvent(ctx, "SELF_MOVE_CREDENTIAL", database.CtEventRealmName, currentRealm, database.CtEventUserID, userID, database.CtEventUsername, username, database.CtEventAdditionalInfo, string(additionalInfos))

	return nil
}
