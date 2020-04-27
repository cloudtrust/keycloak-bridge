package mobilepkg

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Creates constants for API method names
const (
	GetUserInformation = "GetUserInformation"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	logger         log.Logger
	configDBModule keycloakb.ConfigurationDBModule
	next           Component
}

// MakeAuthorizationMobileComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationMobileComponentMW(logger log.Logger, configDBModule keycloakb.ConfigurationDBModule) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			logger:         logger,
			configDBModule: configDBModule,
			next:           next,
		}
	}
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error) {
	// No restriction for this call
	return c.next.GetUserInformation(ctx)
}
