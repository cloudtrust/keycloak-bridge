package idp

import (
	"context"
	"errors"
	"fmt"
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
	GetComponents(accessToken string, realmName string, paramKV ...string) ([]kc.ComponentRepresentation, error)
	CreateComponent(accessToken string, realmName string, comp kc.ComponentRepresentation) error
	UpdateComponent(accessToken string, realmName, compID string, comp kc.ComponentRepresentation) error
	GetIdpMappers(accessToken string, realmName string, idpAlias string) ([]kc.IdentityProviderMapperRepresentation, error)
	CreateIdpMapper(accessToken string, realmName string, idpAlias string, mapperRep kc.IdentityProviderMapperRepresentation) error
	UpdateIdpMapper(accessToken string, realmName string, idpAlias string, mapperID string, mapperRep kc.IdentityProviderMapperRepresentation) error
	DeleteIdpMapper(accessToken string, realmName string, idpAlias string, mapperID string) error
}

// Component interface exposes methods used by the bridge API
type Component interface {
	GetIdentityProvider(ctx context.Context, realmName string, providerAlias string) (api.IdentityProviderRepresentation, error)
	CreateIdentityProvider(ctx context.Context, realmName string, provider api.IdentityProviderRepresentation) error
	UpdateIdentityProvider(ctx context.Context, realmName string, providerAlias string, provider api.IdentityProviderRepresentation) error
	DeleteIdentityProvider(ctx context.Context, realmName string, providerAlias string) error
	GetIdentityProviderMappers(ctx context.Context, realmName string, idpAlias string) ([]api.IdentityProviderMapperRepresentation, error)
	CreateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, apiMapper api.IdentityProviderMapperRepresentation) error
	UpdateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string, apiMapper api.IdentityProviderMapperRepresentation) error
	DeleteIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string) error
}

type component struct {
	keycloakIdpClient KeycloakIdpClient
	tokenProvider     toolbox.OidcTokenProvider
	hrdTool           toolbox.ComponentTool
	logger            internal.Logger
}

// NewComponent returns the communications component.
func NewComponent(keycloakIdpClient KeycloakIdpClient, tokenProvider toolbox.OidcTokenProvider, hrdTool toolbox.ComponentTool, logger internal.Logger) Component {
	return &component{
		keycloakIdpClient: keycloakIdpClient,
		tokenProvider:     tokenProvider,
		hrdTool:           hrdTool,
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

func (c *component) GetIdentityProvider(ctx context.Context, realmName string, idpAlias string) (api.IdentityProviderRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return api.IdentityProviderRepresentation{}, err
	}

	idp, err := c.keycloakIdpClient.GetIdp(accessToken, realmName, idpAlias)
	if err := handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return api.IdentityProviderRepresentation{}, err
	}

	return api.ConvertToAPIIdentityProvider(idp), nil
}

func (c *component) CreateIdentityProvider(ctx context.Context, realmName string, idp api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcIdp := api.ConvertToKCIdentityProvider(idp)
	err = c.keycloakIdpClient.CreateIdp(accessToken, realmName, kcIdp)
	if err != nil {
		return err
	}

	if idp.HrdSettings != nil {
		if err = c.updateHrdConfig(ctx, accessToken, realmName, idp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update HRD configuration", "realm", realmName, "idp", *idp.Alias, "err", err.Error())
			return err
		}
	}

	return nil
}

func (c *component) UpdateIdentityProvider(ctx context.Context, realmName string, idpAlias string, idp api.IdentityProviderRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	idpKc := api.ConvertToKCIdentityProvider(idp)
	err = c.keycloakIdpClient.UpdateIdp(accessToken, realmName, idpAlias, idpKc)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}

func (c *component) DeleteIdentityProvider(ctx context.Context, realmName string, idpAlias string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	err = c.keycloakIdpClient.DeleteIdp(accessToken, realmName, idpAlias)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	if err = c.deleteHrdConfigKeyValue(ctx, accessToken, realmName, idpAlias); err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete HRD configuration", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return err
	}

	return nil
}

func (c *component) findHrdComponent(ctx context.Context, accessToken string, realmName string) (*kc.ComponentRepresentation, error) {
	var additionalParams = []string{}
	additionalParams = append(additionalParams, "type", c.hrdTool.GetProviderType())
	comps, err := c.keycloakIdpClient.GetComponents(accessToken, realmName, additionalParams...)
	if err := handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return nil, err
	}

	if len(comps) == 0 {
		return nil, nil
	}

	return c.hrdTool.FindComponent(comps), nil

}

func (c *component) updateHrdConfig(ctx context.Context, accessToken string, realmName string, idp api.IdentityProviderRepresentation) error {

	hrdComp, err := c.findHrdComponent(ctx, accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get component", "realm", realmName, "err", err.Error())
		return err
	}

	if hrdComp != nil {
		// The component already exists => Update it

		var settings api.HrdSettingModel
		if err = c.hrdTool.GetComponentEntry(hrdComp, *idp.Alias, &settings); err != nil {
			if errors.Is(err, toolbox.ErrConfigKeyNotFound) {
				settings = api.HrdSettingModel{}
			} else {
				c.logger.Warn(ctx, "msg", "Can't get component entry", "realm", realmName, "idp", idp.Alias, "err", err.Error())
				return err
			}
		}

		settings.IPRangesList = idp.HrdSettings.IPRangesList

		if err = c.hrdTool.UpdateComponentEntry(hrdComp, *idp.Alias, settings); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update component entry", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}

		if err = c.keycloakIdpClient.UpdateComponent(accessToken, realmName, *hrdComp.ID, *hrdComp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't update component on Keycloak", "realm", realmName, "component", *hrdComp.ID, "err", err.Error())
			return err
		}

	} else {
		// The component does not exist yet

		comp, err := c.hrdTool.InitializeComponent(realmName, *idp.Alias, idp.HrdSettings)
		if err != nil {
			c.logger.Warn(ctx, "msg", "Can't initialize component", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}

		if err = c.keycloakIdpClient.CreateComponent(accessToken, realmName, comp); err != nil {
			c.logger.Warn(ctx, "msg", "Can't create component in Keycloak", "realm", realmName, "idp", idp.Alias, "err", err.Error())
			return err
		}
	}

	return nil
}

func (c *component) deleteHrdConfigKeyValue(ctx context.Context, accessToken string, realmName string, idpAlias string) error {

	comp, err := c.findHrdComponent(ctx, accessToken, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't get component", "realm", realmName, "err", err.Error())
		return err
	}

	if comp == nil {
		return nil
	}

	deleted, err := c.hrdTool.DeleteComponentEntry(comp, idpAlias)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Can't delete entry", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return fmt.Errorf("failed to delete component entry: %w", err)
	}
	if !deleted {
		// nothing to delete
		return nil
	}

	if err = c.keycloakIdpClient.UpdateComponent(accessToken, realmName, *comp.ID, *comp); err != nil {
		c.logger.Warn(ctx, "msg", "Can't update component", "realm", realmName, "idp", idpAlias, "err", err.Error())
		return err
	}

	return nil
}

func (c *component) GetIdentityProviderMappers(ctx context.Context, realmName string, idpAlias string) ([]api.IdentityProviderMapperRepresentation, error) {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return []api.IdentityProviderMapperRepresentation{}, err
	}

	kcMappers, err := c.keycloakIdpClient.GetIdpMappers(accessToken, realmName, idpAlias)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return []api.IdentityProviderMapperRepresentation{}, err
	}

	return api.ConvertToAPIIdentityProviderMappers(kcMappers), nil
}

func (c *component) CreateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, apiMapper api.IdentityProviderMapperRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcMapper := api.ConvertToKCIdentityProviderMapper(apiMapper)
	err = c.keycloakIdpClient.CreateIdpMapper(accessToken, realmName, idpAlias, kcMapper)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}

func (c *component) UpdateIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string, apiMapper api.IdentityProviderMapperRepresentation) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	kcMapper := api.ConvertToKCIdentityProviderMapper(apiMapper)
	err = c.keycloakIdpClient.UpdateIdpMapper(accessToken, realmName, idpAlias, mapperID, kcMapper)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}

func (c *component) DeleteIdentityProviderMapper(ctx context.Context, realmName string, idpAlias string, mapperID string) error {
	accessToken, err := c.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		c.logger.Warn(ctx, "msg", "Failed to get OIDC token from keycloak", "err", err.Error())
		return err
	}

	err = c.keycloakIdpClient.DeleteIdpMapper(accessToken, realmName, idpAlias, mapperID)
	if err = handleKeycloakIdpError(ctx, err, c.logger); err != nil {
		return err
	}

	return nil
}
