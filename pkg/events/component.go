package events

import (
	"context"

	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	app "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Component is the interface of the events component.
type Component interface {
	GetEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetUserEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
}

type component struct {
	db            app.EventsDBModule
	eventDBModule database.EventsDBModule
}

// NewComponent returns a component
func NewComponent(db app.EventsDBModule, eventDBModule database.EventsDBModule) Component {
	return &component{
		db:            db,
		eventDBModule: eventDBModule,
	}
}

func (ec *component) reportEvent(ctx context.Context, apiCall string, values ...string) error {
	return ec.eventDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
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
	ec.reportEvent(ctx, "GET_ACTIVITY", "realm_name", params["realm"], "user_id", params["userID"])
	return ec.GetEvents(ctx, params)
}
