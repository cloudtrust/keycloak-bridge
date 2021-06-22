package mobilepkg

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

const (
	actionIDNow         = "IDNow"
	idNowInitActionName = "IDN_Init"
)

var mapCheckToAction = map[string]string{
	"IDNOW_CHECK": actionIDNow,
}

func toActionNames(checkNames *[]string) *[]string {
	if checkNames == nil {
		return nil
	}
	var res []string
	for _, checkName := range *checkNames {
		if action, ok := mapCheckToAction[checkName]; ok {
			res = append(res, action)
		} else {
			res = append(res, checkName)
		}
	}
	return &res
}

func chooseNotEmpty(values ...*string) *string {
	for _, value := range values {
		if value != nil && *value != "" {
			return value
		}
	}
	return nil
}

// AppendIDNowActions is used to let the bridge load IDNow rights for IDNow actions (IDN_Init)
func AppendIDNowActions(authActions []string) []string {
	return append(authActions, idNowInitActionName)
}

// KeycloakClient interface exposes methods we need to call to send requests to Keycloak API
type KeycloakClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error)
}

// UsersDetailsDBModule is the minimum required interface to access the users database
type UsersDetailsDBModule interface {
	GetChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error)
}

// TokenProvider is the interface to retrieve accessToken to access KC
type TokenProvider interface {
	ProvideToken(ctx context.Context) (string, error)
}

// AuthorizationManager is the interface to check authorizations of a user
type AuthorizationManager interface {
	CheckAuthorizationOnTargetUser(ctx context.Context, action, targetRealm, userID string) error
}

// Component is the management component
type component struct {
	keycloakClient KeycloakClient
	configDBModule keycloakb.ConfigurationDBModule
	usersDBModule  UsersDetailsDBModule
	tokenProvider  TokenProvider
	authManager    AuthorizationManager
	logger         keycloakb.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakClient KeycloakClient, configDBModule keycloakb.ConfigurationDBModule, usersDBModule UsersDetailsDBModule, tokenProvider TokenProvider, authManager AuthorizationManager, logger keycloakb.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		configDBModule: configDBModule,
		usersDBModule:  usersDBModule,
		tokenProvider:  tokenProvider,
		authManager:    authManager,
		logger:         logger,
	}
}

func (c *component) GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error) {
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var userInfo api.UserInformationRepresentation
	var gln *string
	var pendingChecks *string

	// Get an OIDC token to be able to request Keycloak
	var techAccessToken string
	techAccessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if realmKc, err := c.keycloakClient.GetRealm(techAccessToken, realm); err == nil {
		userInfo.RealmDisplayName = chooseNotEmpty(realmKc.DisplayName, &realm)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if userKc, err := c.keycloakClient.GetUser(techAccessToken, realm, userID); err == nil {
		keycloakb.ConvertLegacyAttribute(&userKc)
		userInfo.SetAccreditations(ctx, userKc.GetAttribute(constants.AttrbAccreditations), c.logger)
		gln = userKc.GetAttributeString(constants.AttrbBusinessID)
		pendingChecks = userKc.GetAttributeString(constants.AttrbPendingChecks)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if dbChecks, err := c.usersDBModule.GetChecks(ctx, realm, userID); err == nil {
		userInfo.SetChecks(dbChecks)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if realmAdminConfig, err := c.configDBModule.GetAdminConfiguration(ctx, realm); err == nil {
		var availableChecks = realmAdminConfig.AvailableChecks
		if gln == nil && realmAdminConfig.ShowGlnEditing != nil && *realmAdminConfig.ShowGlnEditing {
			delete(availableChecks, actionIDNow)
		}
		// User can't execute GetGroupNamesOfUser... use a technical account
		if !c.isIDNowAvailableForUser(ctx, techAccessToken) {
			c.logger.Debug(ctx, "msg", "User is not allowed to access video identification", "id", ctx.Value(cs.CtContextUserID))
			delete(availableChecks, actionIDNow)
		}
		var pendingCheckNames = keycloakb.GetPendingChecks(pendingChecks)
		userInfo.PendingActions = toActionNames(pendingCheckNames)
		if userInfo.PendingActions != nil && len(availableChecks) > 0 {
			for _, action := range *userInfo.PendingActions {
				delete(availableChecks, action)
			}
		}
		userInfo.SetActions(availableChecks)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	return userInfo, nil
}

func (c *component) isIDNowAvailableForUser(ctx context.Context, technicalUserAccessToken string) bool {
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var technicalUserContext = context.WithValue(ctx, cs.CtContextAccessToken, technicalUserAccessToken)

	return c.authManager.CheckAuthorizationOnTargetUser(technicalUserContext, idNowInitActionName, realm, userID) == nil
}
