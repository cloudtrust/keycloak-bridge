package events

import (
	"context"

	"github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
)

// EventsComponent is the interface of the events component.
type EventsComponent interface {
	GetEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetUserEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
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
func (ec *component) GetEvents(ctx context.Context, params map[string]string) (api.AuditEventsRepresentation, error) {
	var empty [0]api.AuditRepresentation
	var res api.AuditEventsRepresentation
	var err error

	res.Events = empty[:]
	res.Count, err = ec.db.GetEventsCount(ctx, params)
	if err == nil && res.Count > 0 {
		res.Events, err = ec.db.GetEvents(ctx, params)
	}

	return res, err
}

// Get all possible values for origin, realm and ctEventType
func (ec *component) GetEventsSummary(ctx context.Context) (api.EventSummaryRepresentation, error) {
	return ec.db.GetEventsSummary(ctx)
}

// Get all events related to a given realm and a given user
func (ec *component) GetUserEvents(ctx context.Context, params map[string]string) (api.AuditEventsRepresentation, error) {
	if val, ok := params["realm"]; !ok || len(val) == 0 {
		return api.AuditEventsRepresentation{}, http.CreateMissingParameterError("realm")
	}
	if val, ok := params["userID"]; !ok || len(val) == 0 {
		return api.AuditEventsRepresentation{}, http.CreateMissingParameterError("userID")
	}
	return ec.GetEvents(ctx, params)
}
