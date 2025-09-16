package components

import (
	"context"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/components"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationCompComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationCompComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) GetComponents(ctx context.Context, realmName string, providerType *string) ([]api.ComponentRepresentation, error) {
	var action = security.COMPGetComponents.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ComponentRepresentation{}, err
	}

	return c.next.GetComponents(ctx, realmName, providerType)
}

func (c *authorizationComponentMW) CreateComponent(ctx context.Context, realmName string, comp api.ComponentRepresentation) error {
	var action = security.COMPCreateComponent.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.CreateComponent(ctx, realmName, comp)
}

func (c *authorizationComponentMW) UpdateComponent(ctx context.Context, realmName string, compID string, comp api.ComponentRepresentation) error {
	var action = security.COMPUpdateComponent.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateComponent(ctx, realmName, compID, comp)
}
