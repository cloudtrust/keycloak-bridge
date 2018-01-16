package components

import (
	"time"
	"context"
	"github.com/go-kit/kit/log"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	sentry "github.com/getsentry/raven-go"
)

/*
Sentry interface
 */
type sentryClient interface {
	SetDSN(dsn string) error
	SetRelease(release string)
	SetEnvironment(environment string)
	SetDefaultLoggerName(name string)
	Capture(packet *sentry.Packet, captureTags map[string]string) (eventID string, ch chan error)
	CaptureMessage(message string, tags map[string]string, interfaces ...sentry.Interface) string
	CaptureMessageAndWait(message string, tags map[string]string, interfaces ...sentry.Interface) string
	CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string
	CaptureErrorAndWait(err error, tags map[string]string, interfaces ...sentry.Interface) string
	CapturePanic(f func(), tags map[string]string, interfaces ...sentry.Interface) (err interface{}, errorID string)
	CapturePanicAndWait(f func(), tags map[string]string, interfaces ...sentry.Interface) (err interface{}, errorID string)
	Close()
	Wait()
	URL() string
	ProjectID() string
	Release() string
	IncludePaths() []string
	SetIncludePaths(p []string)
}


/*
MuxMiddleware is the MuxService middleware
 */
type MuxMiddleware func(MuxService) MuxService

type serviceLoggingMuxMiddleware struct {
	log log.Logger
	next MuxService
}

func (s *serviceLoggingMuxMiddleware) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.Event", "type", eventType, "took", time.Since(begin))
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
Error Middleware
 */
type serviceErrorMiddleware struct {
	log log.Logger
	client sentryClient
	next MuxService
}

func (s *serviceErrorMiddleware) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	var i, err = s.next.Event(ctx, eventType, obj)
	if err != nil {
		s.log.Log("Send error to Sentry:", err)
		s.client.CaptureErrorAndWait(err, nil)
	}
	return i, err
}

func MakeServiceErrorMiddleware(log log.Logger, client sentryClient) MuxMiddleware {
	return func(next MuxService) MuxService {
		return &serviceErrorMiddleware {
			log: log,
			client: client,
			next: next,
		}
	}
}

/*
AdminEventMiddleware is AdminEventService Middleware
 */
type AdminEventMiddleware func(AdminEventService) AdminEventService

type serviceLoggingAdminEventMiddleware struct {
	log log.Logger
	next AdminEventService
}

func (s *serviceLoggingAdminEventMiddleware) AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.AdminEvent", "took", time.Since(begin))
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
EventMiddleware is EventService Middleware
 */
type EventMiddleware func(EventService) EventService

type serviceLoggingEventMiddleware struct {
	log log.Logger
	next EventService
}

func (s *serviceLoggingEventMiddleware) Event(ctx context.Context, event *events.Event) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.Event", "took", time.Since(begin))
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