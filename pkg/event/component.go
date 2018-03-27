package event

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=MuxComponent=MuxComponent,Component=Component,AdminComponent=AdminComponent github.com/cloudtrust/keycloak-bridge/pkg/event MuxComponent,Component,AdminComponent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
)

// MuxComponent is the Mux component interface.
type MuxComponent interface {
	Event(ctx context.Context, eventType string, obj []byte) error
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

func (c *muxComponent) Event(ctx context.Context, eventType string, obj []byte) error {
	switch eventType {
	case "Event":
		var event = fb.GetRootAsEvent(obj, 0)
		return c.component.Event(ctx, event)
	case "AdminEvent":
		var adminEvent = fb.GetRootAsAdminEvent(obj, 0)
		return c.adminComponent.AdminEvent(ctx, adminEvent)
	default:
		return ErrInvalidArgument{InvalidParam: "Type"}
	}
}

// Component is the event component interface.
type Component interface {
	Event(ctx context.Context, event *fb.Event) error
}

type component struct {
	fStdEvent []FuncEvent
	fErrEvent []FuncEvent
}

// NewComponent returns an event component.
func NewComponent(modulesToCallForStandardEvent []FuncEvent,
	modulesToCallForErrorEvent []FuncEvent) Component {
	return &component{
		fStdEvent: modulesToCallForStandardEvent,
		fErrEvent: modulesToCallForErrorEvent,
	}
}

func (c *component) Event(ctx context.Context, event *fb.Event) error {
	var eventType = int(event.Type())
	var eventTypeName = fb.EnumNamesEventType[eventType]
	var eventMap = eventToMap(event)

	if strings.HasSuffix(eventTypeName, "_ERROR") {
		return apply(ctx, c.fErrEvent, eventMap)
	}

	return apply(ctx, c.fStdEvent, eventMap)
}

// AdminComponent is the admin event component interface.
type AdminComponent interface {
	AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error
}

// FuncEvent is the function to call for a given event.
type FuncEvent = func(context.Context, map[string]string) error

type adminComponent struct {
	modulesToCallForCreate []FuncEvent
	modulesToCallForUpdate []FuncEvent
	modulesToCallForDelete []FuncEvent
	modulesToCallForAction []FuncEvent
}

// NewAdminComponent returns an admin event component.
func NewAdminComponent(modulesToCallForCreate []FuncEvent,
	modulesToCallForUpdate []FuncEvent,
	modulesToCallForDelete []FuncEvent,
	modulesToCallForAction []FuncEvent) AdminComponent {
	return &adminComponent{
		modulesToCallForCreate: modulesToCallForCreate,
		modulesToCallForUpdate: modulesToCallForUpdate,
		modulesToCallForDelete: modulesToCallForDelete,
		modulesToCallForAction: modulesToCallForAction,
	}
}

func (c *adminComponent) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	var adminEventMap = adminEventToMap(adminEvent)
	switch operationType := adminEvent.OperationType(); operationType {
	case fb.OperationTypeCREATE:
		return apply(ctx, c.modulesToCallForCreate, adminEventMap)
	case fb.OperationTypeUPDATE:
		return apply(ctx, c.modulesToCallForUpdate, adminEventMap)
	case fb.OperationTypeDELETE:
		return apply(ctx, c.modulesToCallForDelete, adminEventMap)
	case fb.OperationTypeACTION:
		return apply(ctx, c.modulesToCallForAction, adminEventMap)
	default:
		return ErrInvalidArgument{InvalidParam: "OperationType"}
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

func apply(ctx context.Context, fs [](FuncEvent), param map[string]string) error {
	var errors = make(chan error, len(fs))
	var wg sync.WaitGroup

	// Wait for all fs.
	wg.Add(len(fs))

	for _, f := range fs {
		go func(wg *sync.WaitGroup, f FuncEvent) {
			defer wg.Done()

			var err = f(ctx, param)
			if err != nil {
				errors <- err
			}
		}(&wg, f)
	}

	wg.Wait()

	select {
	case err, ok := <-errors:
		if ok {
			return err
		}
	default:
		return nil
	}
	return nil
}
