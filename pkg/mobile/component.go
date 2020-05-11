package mobilepkg

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakAccountClient interface exposes methods we need to call to send requests to Keycloak API of Account
type KeycloakAccountClient interface {
	GetAccount(accessToken, realm string) (kc.UserRepresentation, error)
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error)
}

// UsersDBModule is the minimum required interface to access the users database
type UsersDBModule interface {
	GetUserChecks(ctx context.Context, realm string, userID string) ([]dto.DBCheck, error)
}

// TokenProvider is the interface to retrieve accessToken to access KC
type TokenProvider interface {
	ProvideToken(ctx context.Context) (string, error)
}

// Component is the management component
type component struct {
	keycloakAccountClient KeycloakAccountClient
	configDBModule        keycloakb.ConfigurationDBModule
	usersDBModule         UsersDBModule
	tokenProvider         TokenProvider
	logger                internal.Logger
}

// NewComponent returns the self-service component.
func NewComponent(keycloakAccountClient KeycloakAccountClient, configDBModule keycloakb.ConfigurationDBModule, usersDBModule UsersDBModule, tokenProvider TokenProvider, logger internal.Logger) Component {
	return &component{
		keycloakAccountClient: keycloakAccountClient,
		configDBModule:        configDBModule,
		usersDBModule:         usersDBModule,
		tokenProvider:         tokenProvider,
		logger:                logger,
	}
}

func (c *component) GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error) {
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var userInfo api.UserInformationRepresentation

	// Get an OIDC token to be able to request Keycloak
	var accessToken string
	accessToken, err := c.tokenProvider.ProvideToken(ctx)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get OIDC token", "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if userKc, err := c.keycloakAccountClient.GetAccount(accessToken, realm); err == nil {
		keycloakb.ConvertLegacyAttribute(&userKc)
		userInfo.SetAccreditations(ctx, userKc.GetAttribute(constants.AttrbAccreditations), c.logger)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if dbChecks, err := c.usersDBModule.GetUserChecks(ctx, realm, userID); err == nil {
		userInfo.SetChecks(dbChecks)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	if realmAdminConfig, err := c.configDBModule.GetAdminConfiguration(ctx, realm); err == nil {
		userInfo.SetActions(realmAdminConfig.AvailableChecks)
	} else {
		c.logger.Warn(ctx, "err", err.Error())
		return api.UserInformationRepresentation{}, err
	}

	return userInfo, nil
}
