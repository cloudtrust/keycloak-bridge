package components

import (
	"context"
	"net/http"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/components"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakComponentClient interface exposes methods we need to call to send requests to Keycloak components API
type KeycloakComponentClient interface {
	GetComponents(accessToken string, realmName string, paramKV ...string) ([]kc.ComponentRepresentation, error)
	CreateComponent(accessToken string, realmName string, comp kc.ComponentRepresentation) error
	UpdateComponent(accessToken string, realmName, compID string, comp kc.ComponentRepresentation) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetComponents(ctx context.Context, realmName string, providerType *string) ([]api.ComponentRepresentation, error)
	CreateComponent(ctx context.Context, realmName string, comp api.ComponentRepresentation) error
	UpdateComponent(ctx context.Context, realmName string, compID string, comp api.ComponentRepresentation) error
}

type component struct {
	keycloakComponentClient KeycloakComponentClient
	tokenProvider           toolbox.OidcTokenProvider
	logger                  internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakComponentClient KeycloakComponentClient, tokenProvider toolbox.OidcTokenProvider, logger internal.Logger) Component {
	return &component{
		keycloakComponentClient: keycloakComponentClient,
		tokenProvider:           tokenProvider,
		logger:                  logger,
	}
}

func handleKeycloakComponentError(ctx context.Context, err error, logger internal.Logger) error {
	if err != nil {
		switch e := err.(type) {
		case kc.HTTPError:
			if e.HTTPStatus == http.StatusNotFound {
				logger.Warn(ctx, "msg", "Failed to get component from keycloak", "err", err.Error())
				return errorhandler.CreateNotFoundError("component")
			}
		default:
			return err
		}
	}
	return nil
}

// GetComponents
func (c *component) GetComponents(ctx context.Context, realmName string, providerType *string) ([]api.ComponentRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return []api.ComponentRepresentation{}, err
	}

	var additionalParams = []string{}
	if providerType != nil {
		additionalParams = append(additionalParams, "type", *providerType)
	}

	compsKc, err := c.keycloakComponentClient.GetComponents(accessToken, realmName, additionalParams...)
	if err := handleKeycloakComponentError(ctx, err, c.logger); err != nil {
		return []api.ComponentRepresentation{}, err
	}

	res := []api.ComponentRepresentation{}
	for _, compKc := range compsKc {
		res = append(res, api.ConvertToAPIComponent(compKc))
	}

	return res, nil
}

// CreateComponent
func (c *component) CreateComponent(ctx context.Context, realmName string, compApi api.ComponentRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	compKc := api.ConvertToKCComponent(compApi)
	return c.keycloakComponentClient.CreateComponent(accessToken, realmName, compKc)
}

// UpdateComponent
func (c *component) UpdateComponent(ctx context.Context, realmName string, compID string, apiComp api.ComponentRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	compKc := api.ConvertToKCComponent(apiComp)
	err = c.keycloakComponentClient.UpdateComponent(accessToken, realmName, compID, compKc)
	if err := handleKeycloakComponentError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}
