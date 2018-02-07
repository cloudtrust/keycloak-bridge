package event

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
)

// MuxComponent is the Mux component interface.
type MuxComponent interface {
	Event(ctx context.Context, eventType string, obj []byte) (interface{}, error)
}

type muxComponent struct {
	component      Component
	adminComponent AdminComponent
}

// NewMuxComponent returns a Mux component.
func NewMuxComponent(component Component, adminComponent AdminComponent) MuxComponent {
	return &muxComponent{
		component:      component,
		adminComponent: adminComponent,
	}
}

func (c *muxComponent) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	switch eventType {
	case "Event":
		var event = fb.GetRootAsEvent(obj, 0)
		return c.component.Event(ctx, event)
	case "AdminEvent":
		var adminEvent = fb.GetRootAsAdminEvent(obj, 0)
		return c.adminComponent.AdminEvent(ctx, adminEvent)
	default:
		return nil, ErrInvalidArgument{InvalidParam: "Type"}
	}
}

// Component is the event component interface.
type Component interface {
	Event(ctx context.Context, event *fb.Event) (interface{}, error)
}

type component struct {
	fStdEvent []func(map[string]string) error
	fErrEvent []func(map[string]string) error
}

// NewComponent returns an event component.
func NewComponent(modulesToCallForStandardEvent []func(map[string]string) error,
	modulesToCallForErrorEvent []func(map[string]string) error) Component {
	return &component{
		fStdEvent: modulesToCallForStandardEvent,
		fErrEvent: modulesToCallForErrorEvent,
	}
}

func (c *component) Event(ctx context.Context, event *fb.Event) (interface{}, error) {
	var eventType = int(event.Type())
	var eventTypeName = fb.EnumNamesEventType[eventType]
	var eventMap = eventToMap(event)

	if strings.HasSuffix(eventTypeName, "_ERROR") {
		return apply(c.fErrEvent, eventMap)
	}

	return apply(c.fStdEvent, eventMap)
}

// AdminComponent is the admin event component interface.
type AdminComponent interface {
	AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) (interface{}, error)
}

type adminComponent struct {
	modulesToCallForCreate []func(map[string]string) error
	modulesToCallForUpdate []func(map[string]string) error
	modulesToCallForDelete []func(map[string]string) error
	modulesToCallForAction []func(map[string]string) error
}

// NewAdminComponent returns an admin event component.
func NewAdminComponent(modulesToCallForCreate []func(map[string]string) error,
	modulesToCallForUpdate []func(map[string]string) error,
	modulesToCallForDelete []func(map[string]string) error,
	modulesToCallForAction []func(map[string]string) error) AdminComponent {
	return &adminComponent{
		modulesToCallForCreate: modulesToCallForCreate,
		modulesToCallForUpdate: modulesToCallForUpdate,
		modulesToCallForDelete: modulesToCallForDelete,
		modulesToCallForAction: modulesToCallForAction,
	}
}

func (c *adminComponent) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) (interface{}, error) {
	var adminEventMap = adminEventToMap(adminEvent)
	switch operationType := adminEvent.OperationType(); operationType {
	case fb.OperationTypeCREATE:
		return apply(c.modulesToCallForCreate, adminEventMap)
	case fb.OperationTypeUPDATE:
		return apply(c.modulesToCallForUpdate, adminEventMap)
	case fb.OperationTypeDELETE:
		return apply(c.modulesToCallForDelete, adminEventMap)
	case fb.OperationTypeACTION:
		return apply(c.modulesToCallForAction, adminEventMap)
	default:
		return nil, ErrInvalidArgument{InvalidParam: "OperationType"}
	}
}

func adminEventToMap(adminEvent *fb.AdminEvent) map[string]string {
	var adminEventMap = make(map[string]string)
	adminEventMap["uid"] = fmt.Sprint(adminEvent.Uid())
	adminEventMap["time"] = fmt.Sprint(adminEvent.Time())
	adminEventMap["realmId"] = string(adminEvent.RealmId())
	adminEventMap["authDetails"] = fmt.Sprint(adminEvent.AuthDetails(nil))
	adminEventMap["resourceType"] = string(adminEvent.ResourceType())
	adminEventMap["operationType"] = fb.EnumNamesOperationType[int(adminEvent.OperationType())]
	adminEventMap["resourcePath"] = string(adminEvent.ResourcePath())
	adminEventMap["representation"] = string(adminEvent.Representation())
	adminEventMap["error"] = string(adminEvent.Error())
	return adminEventMap
}

func eventToMap(event *fb.Event) map[string]string {
	var eventMap = make(map[string]string)
	eventMap["uid"] = fmt.Sprint(event.Uid())
	eventMap["time"] = fmt.Sprint(event.Time())
	eventMap["type"] = fb.EnumNamesEventType[int(event.Type())]
	eventMap["realmId"] = string(event.RealmId())
	eventMap["clientId"] = string(event.ClientId())
	eventMap["userId"] = string(event.UserId())
	eventMap["sessionId"] = string(event.SessionId())
	eventMap["ipAddress"] = string(event.IpAddress())
	eventMap["error"] = string(event.Error())

	var detailsString string
	var detailsLength = event.DetailsLength()
	for i := 0; i < detailsLength; i++ {
		var tuple = new(fb.Tuple)
		event.Details(tuple, i)
		detailsString += (string(tuple.Key()) + ":" + string(tuple.Value()) + ",")
	}

	eventMap["details"] = "{" + fmt.Sprint(detailsString) + "}"
	return eventMap
}

func apply(fs [](func(map[string]string) error), param map[string]string) (interface{}, error) {
	var errors = make(chan error, len(fs))
	var wg sync.WaitGroup

	// Wait for all fs.
	wg.Add(len(fs))

	for _, f := range fs {
		go func(wg *sync.WaitGroup, f func(map[string]string) error) {
			defer wg.Done()

			var err = f(param)
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
