package events

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
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
	EVGetActions       = newAction("EV_GetActions", security.ScopeGlobal)
	EVGetEvents        = newAction("EV_GetEvents", security.ScopeRealm)
	EVGetEventsSummary = newAction("EV_GetEventsSummary", security.ScopeGlobal)
	EVGetUserEvents    = newAction("EV_GetUserEvents", security.ScopeGroup)
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
	var action = EVGetActions.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetEvents(ctx context.Context, m map[string]string) (api.AuditEventsRepresentation, error) {
	var action = EVGetEvents.String()

	// For this method, target realm is part of filter params.
	// if no realm filter is provided, there is no target realm thus we use '*'
	var targetRealm, ok = m["realm"]

	if !ok {
		targetRealm = "*"
	}

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.AuditEventsRepresentation{}, err
	}

	return c.next.GetEvents(ctx, m)
}

func (c *authorizationComponentMW) GetEventsSummary(ctx context.Context) (api.EventSummaryRepresentation, error) {
	var action = EVGetEventsSummary.String()
	var targetRealm = "*" // For this method, there is no target realm, as events from any realm can be retrieved the target realm is any realm.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.EventSummaryRepresentation{}, err
	}

	return c.next.GetEventsSummary(ctx)
}

func (c *authorizationComponentMW) GetUserEvents(ctx context.Context, m map[string]string) (api.AuditEventsRepresentation, error) {
	var action = EVGetUserEvents.String()
	var targetRealm = m["realm"] // Get the realm provided as parameter in path
	var targetUser = m["userID"] // Get the user provided as parameter in path

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, targetUser); err != nil {
		return api.AuditEventsRepresentation{}, err
	}

	return c.next.GetUserEvents(ctx, m)
}
