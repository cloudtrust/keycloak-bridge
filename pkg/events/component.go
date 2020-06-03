package events

import (
	"context"

	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	app "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Component is the interface of the events component.
type Component interface {
	GetActions(ctx context.Context) ([]api.ActionRepresentation, error)
	GetEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
	GetEventsSummary(context.Context, map[string]string) (api.EventSummaryRepresentation, error)
	GetUserEvents(context.Context, map[string]string) (api.AuditEventsRepresentation, error)
}

type component struct {
	db            app.EventsDBModule
	eventDBModule database.EventsDBModule
	logger        app.Logger
}

// NewComponent returns a component
func NewComponent(db app.EventsDBModule, eventDBModule database.EventsDBModule, logger app.Logger) Component {
	return &component{
		db:            db,
		eventDBModule: eventDBModule,
		logger:        logger,
	}
}

func (ec *component) reportEvent(ctx context.Context, apiCall string, values ...string) {
	errEvent := ec.eventDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		app.LogUnrecordedEvent(ctx, ec.logger, apiCall, errEvent.Error(), values...)
	}

}

// Get actions
func (ec *component) GetActions(ctx context.Context) ([]api.ActionRepresentation, error) {
	var apiActions = []api.ActionRepresentation{}

	for _, action := range actions {
		var name = action.Name
		var scope = string(action.Scope)

		apiActions = append(apiActions, api.ActionRepresentation{
			Name:  &name,
			Scope: &scope,
		})
	}

	return apiActions, nil
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
func (ec *component) GetEventsSummary(ctx context.Context, params map[string]string) (api.EventSummaryRepresentation, error) {
	return ec.db.GetEventsSummary(ctx)
}

// Get all events related to a given realm and a given user
func (ec *component) GetUserEvents(ctx context.Context, params map[string]string) (api.AuditEventsRepresentation, error) {
	if val, ok := params["realm"]; !ok || len(val) == 0 {
		return api.AuditEventsRepresentation{}, errorhandler.CreateMissingParameterError(msg.Realm)
	}
	if val, ok := params["userID"]; !ok || len(val) == 0 {
		return api.AuditEventsRepresentation{}, errorhandler.CreateMissingParameterError(msg.UserID)
	}

	ec.reportEvent(ctx, "GET_ACTIVITY", database.CtEventRealmName, params["realm"], database.CtEventUserID, params["userID"])
	return ec.GetEvents(ctx, params)
}
