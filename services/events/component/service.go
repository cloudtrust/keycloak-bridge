package components

import (
	"context"
	"fmt"
	"strings"
	"sync"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/http"
)

/*
MuxService is the interface that user services implement.
*/
type MuxService interface {
	Event(ctx context.Context, eventType string, obj []byte) (interface{}, error)
}

//NewMuxService instantiates MuxService
func NewMuxService(eventService EventService, adminEventService AdminEventService) MuxService {
	return &muxService{
		eventService:      eventService,
		adminEventService: adminEventService,
	}
}

type muxService struct {
	eventService      EventService
	adminEventService AdminEventService
}

func (u *muxService) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	switch eventType {
	case "AdminEvent":
		var adminEvent *events.AdminEvent
		adminEvent = events.GetRootAsAdminEvent(obj, 0)
		return u.adminEventService.AdminEvent(ctx, adminEvent)
	case "Event":
		var event *events.Event
		event = events.GetRootAsEvent(obj, 0)
		return u.eventService.Event(ctx, event)
	default:
		var err transport.ErrInvalidArgument
		err.InvalidParam = "Type"
		return nil, err
	}
}

//EventService interface
type EventService interface {
	Event(ctx context.Context, event *events.Event) (interface{}, error)
}

//NewEventService instantiates EventService
func NewEventService(modulesToCallForStandardEvent []func(map[string]string) error,
	modulesToCallForErrorEvent []func(map[string]string) error) EventService {
	return &eventService{
		fnsStandard: modulesToCallForStandardEvent,
		fnsError:    modulesToCallForErrorEvent,
	}
}

type eventService struct {
	fnsStandard []func(map[string]string) error
	fnsError    []func(map[string]string) error
}

func (u *eventService) Event(ctx context.Context, event *events.Event) (interface{}, error) {
	var eventType = int(event.Type())
	var eventTypeName = events.EnumNamesEventType[eventType]
	var eventMap = eventToMap(event)

	if strings.HasSuffix(eventTypeName, "_ERROR") {
		return apply(u.fnsError, eventMap)
	}

	return apply(u.fnsStandard, eventMap)

}

//AdminEventService interface
type AdminEventService interface {
	AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error)
}

//NewAdminEventService instantiates AdminEventService
func NewAdminEventService(modulesToCallForCreate []func(map[string]string) error,
	modulesToCallForUpdate []func(map[string]string) error,
	modulesToCallForDelete []func(map[string]string) error,
	modulesToCallForAction []func(map[string]string) error) AdminEventService {
	return &adminEventService{
		modulesToCallForCreate: modulesToCallForCreate,
		modulesToCallForUpdate: modulesToCallForUpdate,
		modulesToCallForDelete: modulesToCallForDelete,
		modulesToCallForAction: modulesToCallForAction,
	}
}

type adminEventService struct {
	modulesToCallForCreate []func(map[string]string) error
	modulesToCallForUpdate []func(map[string]string) error
	modulesToCallForDelete []func(map[string]string) error
	modulesToCallForAction []func(map[string]string) error
}

func (u *adminEventService) AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	var adminEventMap = adminEventToMap(adminEvent)
	switch operationType := adminEvent.OperationType(); operationType {
	case events.OperationTypeCREATE:
		return apply(u.modulesToCallForCreate, adminEventMap)
	case events.OperationTypeUPDATE:
		return apply(u.modulesToCallForUpdate, adminEventMap)
	case events.OperationTypeDELETE:
		return apply(u.modulesToCallForDelete, adminEventMap)
	case events.OperationTypeACTION:
		return apply(u.modulesToCallForAction, adminEventMap)
	default:
		var err transport.ErrInvalidArgument
		err.InvalidParam = "OperationType"
		return nil, err
	}

	//return nil, nil
}

func adminEventToMap(adminEvent *events.AdminEvent) map[string]string {
	var adminEventMap = make(map[string]string)
	adminEventMap["uid"] = fmt.Sprint(adminEvent.Uid())
	adminEventMap["time"] = fmt.Sprint(adminEvent.Time())
	adminEventMap["realmId"] = string(adminEvent.RealmId())
	adminEventMap["authDetails"] = fmt.Sprint(adminEvent.AuthDetails(nil))
	adminEventMap["resourceType"] = string(adminEvent.ResourceType())
	adminEventMap["operationType"] = events.EnumNamesOperationType[int(adminEvent.OperationType())]
	adminEventMap["resourcePath"] = string(adminEvent.ResourcePath())
	adminEventMap["representation"] = string(adminEvent.Representation())
	adminEventMap["error"] = string(adminEvent.Error())
	return adminEventMap
}

func eventToMap(event *events.Event) map[string]string {
	var eventMap = make(map[string]string)
	eventMap["uid"] = fmt.Sprint(event.Uid())
	eventMap["time"] = fmt.Sprint(event.Time())
	eventMap["type"] = events.EnumNamesEventType[int(event.Type())]
	eventMap["realmId"] = string(event.RealmId())
	eventMap["clientId"] = string(event.ClientId())
	eventMap["userId"] = string(event.UserId())
	eventMap["sessionId"] = string(event.SessionId())
	eventMap["ipAddress"] = string(event.IpAddress())
	eventMap["error"] = string(event.Error())

	var detailsString string
	var detailsLength = event.DetailsLength()
	for i := 0; i < detailsLength; i++ {
		var tuple = new(events.Tuple)
		event.Details(tuple, i)
		detailsString += (string(tuple.Key()) + ":" + string(tuple.Value()) + ",")
	}

	eventMap["details"] = "{" + fmt.Sprint(detailsString) + "}"
	return eventMap
}

func apply(funcs [](func(map[string]string) error), param map[string]string) (interface{}, error) {

	var errors = make(chan error, len(funcs))
	var wg sync.WaitGroup

	//Wait for the execution of all the function of the array
	wg.Add(len(funcs))

	for _, f := range funcs {
		go func(wg1 *sync.WaitGroup, fn func(map[string]string) error) {
			defer wg1.Done()

			var err = fn(param)
			if err != nil {
				errors <- err
			}
		}(&wg, f)
	}

	wg.Wait()

	select {
	case err, ok := <-errors:
		if ok {
			return nil, err
		}
	default:
		return "ok", nil
	}

	return "ok", nil
}
