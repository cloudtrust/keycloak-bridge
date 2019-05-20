package events

import (
	"context"

	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/go-kit/kit/log"
)

// Actions used for authorization module
const (
	EVGetEvents        = "EV_GetEvents"
	EVGetEventsSummary = "EV_GetEventsSummary"
	EVGetUserEvents    = "EV_GetUserEvents"
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        EventsComponent
}

// MakeAuthorizationManagementComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationManagementComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(EventsComponent) EventsComponent {
	return func(next EventsComponent) EventsComponent {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) GetEvents(ctx context.Context, m map[string]string) (api.AuditEventsRepresentation, error) {
	var action = EVGetEvents
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.AuditEventsRepresentation{}, err
	}

	return c.next.GetEvents(ctx, m)
}

func (c *authorizationComponentMW) GetEventsSummary(ctx context.Context) (api.EventSummaryRepresentation, error) {
	var action = EVGetEventsSummary
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.EventSummaryRepresentation{}, err
	}

	return c.next.GetEventsSummary(ctx)
}

func (c *authorizationComponentMW) GetUserEvents(ctx context.Context, m map[string]string) (api.AuditEventsRepresentation, error) {
	var action = EVGetUserEvents
	var targetRealm = m["realm"] // Get the realm provided as parameter in path
	var targetUser = m["userID"] // Get the user provided as parameter in path

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, targetUser); err != nil {
		return api.AuditEventsRepresentation{}, err
	}

	return c.next.GetUserEvents(ctx, m)
}
