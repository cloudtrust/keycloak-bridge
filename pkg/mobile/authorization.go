package mobilepkg

import (
	"context"

	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/mobile"
)

// Creates constants for API method names
const (
	GetUserInformation = "GetUserInformation"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	logger log.Logger
	next   Component
}

// MakeAuthorizationMobileComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationMobileComponentMW(logger log.Logger) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			logger: logger,
			next:   next,
		}
	}
}

func (c *authorizationComponentMW) GetUserInformation(ctx context.Context) (api.UserInformationRepresentation, error) {
	// No restriction for this call
	return c.next.GetUserInformation(ctx)
}
