package statistics

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
)

var actions []string

type Action int

func (a Action) String() string {
	return actions[int(a)]
}

func customIota(s string) Action {
	actions = append(actions, s)
	return Action(len(actions) - 1)
}

// Actions used for authorization module
var (
	STGetActions                      = customIota("ST_GetActions")
	STGetStatistics                   = customIota("ST_GetStatistics")
	STGetStatisticsUsers              = customIota("ST_GetStatisticsUsers")
	STGetStatisticsAuthenticators     = customIota("ST_GetStatisticsAuthenticators")
	STGetStatisticsAuthentications    = customIota("ST_GetStatisticsAuthentications")
	STGetStatisticsAuthenticationsLog = customIota("ST_GetStatisticsAuthenticationsLog")
	STGetMigrationReport              = customIota("ST_GetMigrationReport")
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

func (c *authorizationComponentMW) GetActions(ctx context.Context) ([]string, error) {
	var action = STGetActions.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []string{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetStatistics(ctx context.Context, realm string) (api.StatisticsRepresentation, error) {
	var action = STGetStatistics.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.StatisticsRepresentation{}, err
	}

	return c.next.GetStatistics(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsUsers(ctx context.Context, realm string) (api.StatisticsUsersRepresentation, error) {
	var action = STGetStatisticsUsers.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.StatisticsUsersRepresentation{}, err
	}

	return c.next.GetStatisticsUsers(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsAuthenticators(ctx context.Context, realm string) (map[string]int64, error) {
	var action = STGetStatisticsAuthenticators.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthenticators(ctx, realm)
}

func (c *authorizationComponentMW) GetStatisticsAuthentications(ctx context.Context, realm string, unit string, timeshift *string) ([][]int64, error) {
	var action = STGetStatisticsAuthentications.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthentications(ctx, realm, unit, timeshift)
}

func (c *authorizationComponentMW) GetStatisticsAuthenticationsLog(ctx context.Context, realm string, max string) ([]api.StatisticsConnectionRepresentation, error) {
	var action = STGetStatisticsAuthenticationsLog.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return nil, err
	}

	return c.next.GetStatisticsAuthenticationsLog(ctx, realm, max)
}

func (c *authorizationComponentMW) GetMigrationReport(ctx context.Context, realm string) (map[string]bool, error) {
	var action = STGetMigrationReport.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return map[string]bool{}, err
	}

	return c.next.GetMigrationReport(ctx, realm)
}
