package idp

import (
	"context"
	"net/http"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakIdpClient interface exposes methods we need to call to send requests to Keycloak identity providers API
type KeycloakIdpClient interface {
	GetIdp(accessToken string, realmName string, idpAlias string) (kc.IdentityProviderRepresentation, error)
	CreateIdp(accessToken string, realmName string, idpRep kc.IdentityProviderRepresentation) error
	UpdateIdp(accessToken string, realmName, idpAlias string, idpRep kc.IdentityProviderRepresentation) error
	DeleteIdp(accessToken string, realmName string, idpAlias string) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetIdentityProvider(ctx context.Context, realmName string, providerAlias string) (api.IdentityProviderRepresentation, error)
	CreateIdentityProvider(ctx context.Context, realmName string, provider api.IdentityProviderRepresentation) error
	UpdateIdentityProvider(ctx context.Context, realmName string, providerAlias string, provider api.IdentityProviderRepresentation) error
	DeleteIdentityProvider(ctx context.Context, realmName string, providerAlias string) error
}

type component struct {
	keycloakIdpClient KeycloakIdpClient
	tokenProvider     toolbox.OidcTokenProvider
	logger            internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakIdpClient KeycloakIdpClient, tokenProvider toolbox.OidcTokenProvider, logger internal.Logger) Component {
	return &component{
		keycloakIdpClient: keycloakIdpClient,
		tokenProvider:     tokenProvider,
		logger:            logger,
	}
}

func handleKeycloakIdpError(ctx context.Context, err error, logger internal.Logger) error {
	if err != nil {
		switch e := err.(type) {
		case kc.HTTPError:
			if e.HTTPStatus == http.StatusNotFound {
				logger.Warn(ctx, "msg", "Failed to get identity provider from keycloak", "err", err.Error())
				return errorhandler.CreateNotFoundError("idp")
			}
		default:
			return err
		}
	}
	return nil
}

func (c *component) GetIdentityProvider(ctx context.Context, realmName string, providerAlias string) (api.IdentityProviderRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return api.IdentityProviderRepresentation{}, err
	}

	idp, err := c.keycloakIdpClient.GetIdp(accessToken, realmName, providerAlias)
	if err := handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return api.IdentityProviderRepresentation{}, err
	}

	return api.ConvertToAPIIdentityProvider(idp), nil
}

func (c *component) CreateIdentityProvider(ctx context.Context, realmName string, provider api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	idpKc := api.ConvertToKCIdentityProvider(provider)
	return c.keycloakIdpClient.CreateIdp(accessToken, realmName, idpKc)

}

func (c *component) UpdateIdentityProvider(ctx context.Context, realmName string, providerAlias string, provider api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	idpKc := api.ConvertToKCIdentityProvider(provider)
	err = c.keycloakIdpClient.UpdateIdp(accessToken, realmName, providerAlias, idpKc)
	if err := handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil

}

func (c *component) DeleteIdentityProvider(ctx context.Context, realmName string, providerAlias string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	err = c.keycloakIdpClient.DeleteIdp(accessToken, realmName, providerAlias)
	if err := handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}
