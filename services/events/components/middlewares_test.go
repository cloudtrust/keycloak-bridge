package components

import (
	"testing"
	"context"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
	sentry "github.com/getsentry/raven-go"
	"time"
)

func TestEventMiddlewareComponents_LoggingMuxMiddleware(t *testing.T) {
	var mockMuxService MuxService = &mockMuxService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	var m MuxService = MakeServiceLoggingMuxMiddleware(mockLogger)(mockMuxService)
	m.Event(nil, "test", nil)
	assert.True(t, called)
}

func TestErrorMiddlewareComponents_LoggingErrorMiddleware(t *testing.T) {
	var mockMuxService MuxService = &mockMuxServiceErr{}
	var calledLog bool = false
	var calledSentry bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &calledLog }
	var mockSentry sentryClient = &mockSentry{ Called : &calledSentry }

	var m MuxService = MakeServiceErrorMiddleware(mockLogger, mockSentry)(mockMuxService)
	m.Event(nil, "test", nil)
	assert.True(t, calledLog)
	assert.True(t, calledSentry)
}


func TestEventMiddlewareComponents_LoggingAdminEventMiddleware(t *testing.T) {
	var mockAdminEventService AdminEventService = &mockAdminEventService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	var m AdminEventService = MakeServiceLoggingAdminEventMiddleware(mockLogger)(mockAdminEventService)
	m.AdminEvent(nil,nil)
	assert.True(t, called)
}


func TestEventMiddlewareComponents_LoggingEventMiddleware(t *testing.T) {
	var mockEventService EventService = &mockEventService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	var m EventService = MakeServiceLoggingEventMiddleware(mockLogger)(mockEventService)
	m.Event(nil,nil)
	assert.True(t, called)
}


/*
Mock MuxService for Testing
 */
type mockMuxService struct {}

func (u *mockMuxService) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, nil
}

/*
Mock AdminEventService for Testing
 */
type mockAdminEventService struct {}

func (u *mockAdminEventService) AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	return "", nil
}

/*
Mock EventService for Testing
 */
type mockEventService struct {}

func (u *mockEventService) Event(ctx context.Context, event *events.Event) (interface{}, error) {
	return "", nil
}

/*
Mock Logger for testing
 */
type mockLogger struct {
	Called *bool
}

func (l *mockLogger) Log(keyvals ...interface{}) error{
	*(l.Called) = true
	fmt.Println(keyvals)
	return nil
}

/*
Mock for sentry
 */
type mockSentry struct {
	Called *bool
}

func (client *mockSentry) CaptureErrorAndWait(err error, tags map[string]string, interfaces ...sentry.Interface) string {
	*(client.Called) = true
	fmt.Println(err)
	return ""
}

func (client *mockSentry) SetDSN(dsn string) error {return nil}
func (client *mockSentry) SetRelease(release string) {}
func (client *mockSentry) SetEnvironment(environment string) {}
func (client *mockSentry) SetDefaultLoggerName(name string) {}
func (client *mockSentry) Capture(packet *sentry.Packet, captureTags map[string]string) (eventID string, ch chan error) {return "", nil}
func (client *mockSentry) CaptureMessage(message string, tags map[string]string, interfaces ...sentry.Interface) string {return ""}
func (client *mockSentry) CaptureMessageAndWait(message string, tags map[string]string, interfaces ...sentry.Interface) string {return ""}
func (client *mockSentry) CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string {return ""}
func (client *mockSentry) CapturePanic(f func(), tags map[string]string, interfaces ...sentry.Interface) (err interface{}, errorID string) {return nil, ""}
func (client *mockSentry) CapturePanicAndWait(f func(), tags map[string]string, interfaces ...sentry.Interface) (err interface{}, errorID string) {return nil, ""}
func (client *mockSentry) Close() {}
func (client *mockSentry) Wait() {}
func (client *mockSentry) URL() string {return ""}
func (client *mockSentry) ProjectID() string {return ""}
func (client *mockSentry) Release() string {return ""}
func (client *mockSentry) IncludePaths() []string {return nil}
func (client *mockSentry) SetIncludePaths(p []string) {}

/*
Mock MuxService returning an error for testing Sentry
 */
type mockMuxServiceErr struct {}

type MyError struct {
	When time.Time
	What string
}

func (e MyError) Error() string {
	return fmt.Sprintf("%v: %v", e.When, e.What)
}

func (u *mockMuxServiceErr) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, MyError{time.Now(), "Error for Sentry"}
}
