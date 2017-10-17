package components

import (
	"time"
	"context"
	"github.com/go-kit/kit/log"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
)

/*
MuxService Middleware
 */
type MuxMiddleware func(MuxService) MuxService

type serviceLoggingMuxMiddleware struct {
	log log.Logger
	next MuxService
}

func (s *serviceLoggingMuxMiddleware)Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Event", "type", eventType, "took", time.Since(begin))
	}(time.Now())
	return s.next.Event(ctx, eventType, obj)
}


func MakeServiceLoggingMuxMiddleware(log log.Logger) MuxMiddleware {
	return func(next MuxService) MuxService{
		return &serviceLoggingMuxMiddleware {
			log: log,
			next: next,
		}
	}
}


/*
AdminEventService Middleware
 */

type AdminEventMiddleware func(AdminEventService) AdminEventService

type serviceLoggingAdminEventMiddleware struct {
	log log.Logger
	next AdminEventService
}

func (s *serviceLoggingAdminEventMiddleware)AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "AdminEvent", "took", time.Since(begin))
	}(time.Now())
	return s.next.AdminEvent(ctx, adminEvent)
}

func MakeServiceLoggingAdminEventMiddleware(log log.Logger) AdminEventMiddleware {
	return func(next AdminEventService) AdminEventService{
		return &serviceLoggingAdminEventMiddleware {
			log: log,
			next: next,
		}
	}
}

/*
EventService Middleware
 */

type EventMiddleware func(EventService) EventService

type serviceLoggingEventMiddleware struct {
	log log.Logger
	next EventService
}

func (s *serviceLoggingEventMiddleware)Event(ctx context.Context, event *events.Event) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Event", "took", time.Since(begin))
	}(time.Now())
	return s.next.Event(ctx, event)
}

func MakeServiceLoggingEventMiddleware(log log.Logger) EventMiddleware {
	return func(next EventService) EventService{
		return &serviceLoggingEventMiddleware {
			log: log,
			next: next,
		}
	}
}