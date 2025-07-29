package idp

import (
	"context"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationIdpComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationIdpComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) GetIdentityProvider(ctx context.Context, realmName string, providerAlias string) (api.IdentityProviderRepresentation, error) {
	var action = security.IDPGetIdentityProvider.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.IdentityProviderRepresentation{}, err
	}

	return c.next.GetIdentityProvider(ctx, realmName, providerAlias)
}

func (c *authorizationComponentMW) CreateIdentityProvider(ctx context.Context, realmName string, provider api.IdentityProviderRepresentation) error {
	var action = security.IDPCreateIdentityProvider.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.CreateIdentityProvider(ctx, realmName, provider)
}

func (c *authorizationComponentMW) UpdateIdentityProvider(ctx context.Context, realmName string, providerAlias string, provider api.IdentityProviderRepresentation) error {
	var action = security.IDPUpdateIdentityProvider.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateIdentityProvider(ctx, realmName, providerAlias, provider)
}

func (c *authorizationComponentMW) DeleteIdentityProvider(ctx context.Context, realmName string, providerAlias string) error {
	var action = security.IDPDeleteIdentityProvider.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.DeleteIdentityProvider(ctx, realmName, providerAlias)
}
