package statistics

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
)

// Actions used for authorization module
const (
	STGetStatistics      = "ST_GetStatistics"
	STGetMigrationReport = "ST_GetMigrationReport"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationManagementComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationManagementComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) GetStatistics(ctx context.Context, realm string) (api.StatisticsRepresentation, error) {
	var action = STGetStatistics

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.StatisticsRepresentation{}, err
	}

	return c.next.GetStatistics(ctx, realm)
}

func (c *authorizationComponentMW) GetMigrationReport(ctx context.Context, realm string) (map[string]bool, error) {
	var action = STGetMigrationReport

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return map[string]bool{}, err
	}

	return c.next.GetMigrationReport(ctx, realm)
}
