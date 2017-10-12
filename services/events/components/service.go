package components

import (
	"context"
	"github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport"
	"github.com/asaskevich/EventBus"
)

/*
This is the interface that user services implement.
 */
type MuxService interface {
	Event(ctx context.Context, eventType string, obj []byte) (interface{}, error)
}


/*
 */
func NewBasicMuxService(bus EventBus.Bus) MuxService {
	return &basicMuxService{
		bus:bus,
	}
}

type basicMuxService struct {
	bus EventBus.Bus
}

func (u *basicMuxService)Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	switch eventType {
	case "AdminEvent":
		var adminEvent *events.AdminEvent
		adminEvent= events.GetRootAsAdminEvent(obj, 0)
		u.bus.Publish("main:AdminEvent", ctx, adminEvent)
		return "ok", nil
	case "Event":
		var event *events.Event
		event= events.GetRootAsEvent(obj, 0)
		u.bus.Publish("main:Event", ctx, event)
		return "ok", nil
	default:
		var err transport.ErrInvalidArgument
		err.InvalidParam = "Type"
		return "bad", err
	}
}


type Service interface {
	Event(ctx context.Context, event events.Event) (interface{}, error)
	AdminEvent(ctx context.Context, adminEvent events.AdminEvent) (interface{}, error)
}



/*
 */
func NewBasicService(console console.Service) Service {
	return &basicService{
		module: console,
	}
}

type basicService struct {
	module console.Service
}

func (u *basicService)Event(ctx context.Context, event events.Event) (interface{}, error) {
	u.module.Print(ctx, "Event", string(event.Uid()), string(event.Time()))
	return nil, nil
}

func (u *basicService)AdminEvent(ctx context.Context, adminEvent events.AdminEvent) (interface{}, error) {
	u.module.Print(ctx, "AdminEvent", string(adminEvent.Uid()), string(adminEvent.Time()))
	return nil, nil
}