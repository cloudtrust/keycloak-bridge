package events

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
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
	EVGetActions       = customIota("EV_GetActions")
	EVGetEvents        = customIota("EV_GetEvents")
	EVGetEventsSummary = customIota("EV_GetEventsSummary")
	EVGetUserEvents    = customIota("EV_GetUserEvents")
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
	var action = EVGetActions.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []string{}, err
	}

	return c.next.GetActions(ctx)
}

func (c *authorizationComponentMW) GetEvents(ctx context.Context, m map[string]string) (api.AuditEventsRepresentation, error) {
	var action = EVGetEvents.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.AuditEventsRepresentation{}, err
	}

	return c.next.GetEvents(ctx, m)
}

func (c *authorizationComponentMW) GetEventsSummary(ctx context.Context) (api.EventSummaryRepresentation, error) {
	var action = EVGetEventsSummary.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

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
