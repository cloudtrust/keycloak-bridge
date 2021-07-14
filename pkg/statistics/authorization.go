package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
)

var actions []security.Action

func newAction(as string, scope security.Scope) security.Action {
	a := security.Action{
		Name:  as,
		Scope: scope,
	}

	actions = append(actions, a)
	return a
}

// Actions used for authorization module
var (
	STGetActions                      = newAction("ST_GetActions", security.ScopeGlobal)
	STGetStatistics                   = newAction("ST_GetStatistics", security.ScopeRealm)
	STGetStatisticsIdentifications    = newAction("ST_GetStatisticsIdentifications", security.ScopeRealm)
	STGetStatisticsUsers              = newAction("ST_GetStatisticsUsers", security.ScopeRealm)
	STGetStatisticsAuthenticators     = newAction("ST_GetStatisticsAuthenticators", security.ScopeRealm)
	STGetStatisticsAuthentications    = newAction("ST_GetStatisticsAuthentications", security.ScopeRealm)
	STGetStatisticsAuthenticationsLog = newAction("ST_GetStatisticsAuthenticationsLog", security.ScopeRealm)
	STGetMigrationReport              = newAction("ST_GetMigrationReport", security.ScopeRealm)
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// GetActions returns available actions
func GetActions() []security.Action {
	return actions
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
	var action = STGetActions.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ActionRepresentation{}, err
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

func (c *authorizationComponentMW) GetStatisticsIdentifications(ctx context.Context, realm string) (api.IdentificationStatisticsRepresentation, error) {
	var action = STGetStatisticsIdentifications.String()

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, realm); err != nil {
		return api.IdentificationStatisticsRepresentation{}, err
	}

	return c.next.GetStatisticsIdentifications(ctx, realm)
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
