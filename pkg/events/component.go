package events

import (
	"context"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// EventsComponent is the interface of the events component.
type EventsComponent interface {
	GetEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetUserEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
}

type component struct {
	db EventsDBModule
}

// NewEventsComponent returns an events DB module
func NewEventsComponent(db EventsDBModule) EventsComponent {
	return &component{
		db: db,
	}
}

// Get events according to optional parameters
func (ec *component) GetEvents(ctx context.Context, params map[string]string) ([]api.AuditRepresentation, error) {
	return ec.db.GetEvents(ctx, params)
}

// Get all possible values for origin, realm and ctEventType
func (ec *component) GetEventsSummary(ctx context.Context) (api.EventSummaryRepresentation, error) {
	return ec.db.GetEventsSummary(ctx)
}

// Get all events related to a given realm and a given user
func (ec *component) GetUserEvents(ctx context.Context, params map[string]string) ([]api.AuditRepresentation, error) {
	if val, ok := params["realm"]; !ok || len(val) == 0 {
		return []api.AuditRepresentation{}, keycloakb.CreateMissingParameterError("realm")
	}
	if val, ok := params["userID"]; !ok || len(val) == 0 {
		return []api.AuditRepresentation{}, keycloakb.CreateMissingParameterError("userID")
	}
	return ec.db.GetEvents(ctx, params)
}
