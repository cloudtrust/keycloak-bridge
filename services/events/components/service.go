package components

import (
	"context"
	"github.com/cloudtrust/keycloak-bridge/services/events/modules/console"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport"
)

/*
This is the interface that user services implement.
 */
type Service interface {
	Event(ctx context.Context, eventType string, obj []byte) (interface{}, error)
}

/*
 */
func NewBasicService(consoleModule console.Service) Service {
	return &basicService{
		module:consoleModule,
	}
}

type basicService struct {
	module console.Service
}

func (u *basicService)Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	switch eventType {
	case "AdminEvent":
		var adminEvent *events.AdminEvent
		adminEvent= events.GetRootAsAdminEvent(obj, 0)
		u.module.Print(ctx, string(adminEvent.Uid()), string(adminEvent.Time()))
		return "ok", nil
	case "Event":
		var event *events.Event
		event= events.GetRootAsEvent(obj, 0)
		u.module.Print(ctx, string(event.Uid()), string(event.Time()))
		return "ok", nil
	default:
		var err transport.ErrInvalidArgument
		err.InvalidParam = "Type"
		return "bad", err
	}
}
