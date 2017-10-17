package components

import (
	"testing"
	"context"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/events"
)



func TestEventMiddlewareComponents_LoggingMuxMiddleware(t *testing.T) {
	var mockMuxService MuxService = &mockMuxService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	m := MakeServiceLoggingMuxMiddleware(mockLogger)(mockMuxService)
	m.Event(nil, "test", nil)
	assert.True(t, called)
}


func TestEventMiddlewareComponents_LoggingAdminEventMiddleware(t *testing.T) {
	var mockAdminEventService AdminEventService = &mockAdminEventService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	m := MakeServiceLoggingAdminEventMiddleware(mockLogger)(mockAdminEventService)
	m.AdminEvent(nil,nil)
	assert.True(t, called)
}


func TestEventMiddlewareComponents_LoggingEventMiddleware(t *testing.T) {
	var mockEventService EventService = &mockEventService{}
	var called bool = false
	var mockLogger log.Logger = &mockLogger{ Called : &called}

	m := MakeServiceLoggingEventMiddleware(mockLogger)(mockEventService)
	m.Event(nil,nil)
	assert.True(t, called)
}



/*
Mock MuxService for Testing
 */
type mockMuxService struct {}

func (u *mockMuxService)Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, nil
}

/*
Mock AdminEventService for Testing
 */
type mockAdminEventService struct {}

func (u *mockAdminEventService)AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	return "", nil
}

/*
Mock EventService for Testing
 */
type mockEventService struct {}

func (u *mockEventService)Event(ctx context.Context, event *events.Event) (interface{}, error) {
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

