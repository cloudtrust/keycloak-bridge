package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
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

func (c *authorizationComponentMW) GetActions(ctx context.Context) ([]api.ActionRepresentation, error) {
	var action = security.STGetActions.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetStatistics(ctx context.Context, realm string) (api.StatisticsRepresentation, error) {
	var action = security.STGetStatistics.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.StatisticsRepresentation{}, err
	}

	return c.next.GetStatistics(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsIdentifications(ctx context.Context, realm string) (api.IdentificationStatisticsRepresentation, error) {
	var action = security.STGetStatisticsIdentifications.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.IdentificationStatisticsRepresentation{}, err
	}

	return c.next.GetStatisticsIdentifications(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsUsers(ctx context.Context, realm string) (api.StatisticsUsersRepresentation, error) {
	var action = security.STGetStatisticsUsers.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.StatisticsUsersRepresentation{}, err
	}

	return c.next.GetStatisticsUsers(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsAuthenticators(ctx context.Context, realm string) (map[string]int64, error) {
	var action = security.STGetStatisticsAuthenticators.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthenticators(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsAuthentications(ctx context.Context, realm string, unit string, timeshift *string) ([][]int64, error) {
	var action = security.STGetStatisticsAuthentications.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthentications(ctx, realm, unit, timeshift)
}

func (c *authorizationComponentMW) GetStatisticsAuthenticationsLog(ctx context.Context, realm string, max string) ([]api.StatisticsConnectionRepresentation, error) {
	var action = security.STGetStatisticsAuthenticationsLog.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthenticationsLog(ctx, realm, max)
}

func (c *authorizationComponentMW) GetMigrationReport(ctx context.Context, realm string) (map[string]bool, error) {
	var action = security.STGetMigrationReport.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return map[string]bool{}, err
	}

	return c.next.GetMigrationReport(ctx, realm)
}
