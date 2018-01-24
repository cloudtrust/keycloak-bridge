package components

import (
	"context"
	"time"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
	sentry "github.com/getsentry/raven-go"
	"github.com/go-kit/kit/log"
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
	log  log.Logger
	next MuxService
}

func (s *serviceLoggingMuxMiddleware) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.Event", "type", eventType, "id", ctx.Value("id").(string), "took", time.Since(begin))
	}(time.Now())
	return s.next.Event(ctx, eventType, obj)
}

//MakeServiceLoggingMuxMiddleware wraps the MuxService with logging
func MakeServiceLoggingMuxMiddleware(log log.Logger) MuxMiddleware {
	return func(next MuxService) MuxService {
		return &serviceLoggingMuxMiddleware{
			log:  log,
			next: next,
		}
	}
}

/*
Error Middleware
*/
type serviceErrorMiddleware struct {
	log    log.Logger
	client sentryClient
	next   MuxService
}

func (s *serviceErrorMiddleware) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	var i, err = s.next.Event(ctx, eventType, obj)
	if err != nil {
		s.log.Log("msg", "Send error to Sentry", "id", ctx.Value("id").(string), "error", err)
		s.client.CaptureErrorAndWait(err, nil)
	}
	return i, err
}

//MakeServiceErrorMiddleware wraps the MuxService with error tracking
func MakeServiceErrorMiddleware(log log.Logger, client sentryClient) MuxMiddleware {
	return func(next MuxService) MuxService {
		return &serviceErrorMiddleware{
			log:    log,
			client: client,
			next:   next,
		}
	}
}

/*
AdminEventMiddleware is AdminEventService Middleware
*/
type AdminEventMiddleware func(AdminEventService) AdminEventService

type serviceLoggingAdminEventMiddleware struct {
	log  log.Logger
	next AdminEventService
}

func (s *serviceLoggingAdminEventMiddleware) AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.AdminEvent", "id", ctx.Value("id").(string), "took", time.Since(begin))
	}(time.Now())
	return s.next.AdminEvent(ctx, adminEvent)
}

//MakeServiceLoggingAdminEventMiddleware wraps AdminEventService with logging
func MakeServiceLoggingAdminEventMiddleware(log log.Logger) AdminEventMiddleware {
	return func(next AdminEventService) AdminEventService {
		return &serviceLoggingAdminEventMiddleware{
			log:  log,
			next: next,
		}
	}
}

/*
EventMiddleware is EventService Middleware
*/
type EventMiddleware func(EventService) EventService

type serviceLoggingEventMiddleware struct {
	log  log.Logger
	next EventService
}

func (s *serviceLoggingEventMiddleware) Event(ctx context.Context, event *events.Event) (interface{}, error) {
	defer func(begin time.Time) {
		s.log.Log("method", "Component.Event", "id", ctx.Value("id").(string), "took", time.Since(begin))
	}(time.Now())
	return s.next.Event(ctx, event)
}

//MakeServiceLoggingEventMiddleware wraps the EventService with logging
func MakeServiceLoggingEventMiddleware(log log.Logger) EventMiddleware {
	return func(next EventService) EventService {
		return &serviceLoggingEventMiddleware{
			log:  log,
			next: next,
		}
	}
}
