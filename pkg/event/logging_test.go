package event

import (
	"fmt"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
)

func TestEventMiddlewareComponents_LoggingMuxMiddleware(t *testing.T) {
	var mockMuxService MuxService = &mockMuxService{}
	var called = false
	var mockLogger log.Logger = &mockLogger{Called: &called}

	var m = MakeServiceLoggingMuxMiddleware(mockLogger)(mockMuxService)
	m.Event(nil, "test", nil)
	assert.True(t, called)
}
func TestEventMiddlewareComponents_LoggingAdminEventMiddleware(t *testing.T) {
	var mockAdminEventService AdminEventService = &mockAdminEventService{}
	var called = false
	var mockLogger log.Logger = &mockLogger{Called: &called}

	var m = MakeServiceLoggingAdminEventMiddleware(mockLogger)(mockAdminEventService)
	m.AdminEvent(nil, nil)
	assert.True(t, called)
}

func TestEventMiddlewareComponents_LoggingEventMiddleware(t *testing.T) {
	var mockEventService EventService = &mockEventService{}
	var called = false
	var mockLogger log.Logger = &mockLogger{Called: &called}

	var m = MakeServiceLoggingEventMiddleware(mockLogger)(mockEventService)
	m.Event(nil, nil)
	assert.True(t, called)
}

/*
Mock Logger for testing
*/
type mockLogger struct {
	Called *bool
}

func (l *mockLogger) Log(keyvals ...interface{}) error {
	*(l.Called) = true
	fmt.Println(keyvals)
	return nil
}
