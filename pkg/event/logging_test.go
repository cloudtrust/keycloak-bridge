package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventMiddlewareComponents_LoggingMuxMiddleware(t *testing.T) {
	var mockMuxComponent MuxComponent = &mockMuxComponent{}
	var mockLogger = &mockLogger{Called: false}

	var m = MakeMuxComponentLoggingMW(mockLogger)(mockMuxComponent)
	m.Event(nil, "test", nil)
	assert.True(t, mockLogger.Called)
}
func TestEventMiddlewareComponents_LoggingAdminEventMiddleware(t *testing.T) {
	var mockAdminComponent AdminComponent = &mockAdminComponent{}
	var mockLogger = &mockLogger{Called: false}

	var m = MakeAdminComponentLoggingMW(mockLogger)(mockAdminComponent)
	m.AdminEvent(nil, nil)
	assert.True(t, mockLogger.Called)
}

func TestEventMiddlewareComponents_LoggingEventMiddleware(t *testing.T) {
	var mockComponent Component = &mockComponent{}
	var mockLogger = &mockLogger{Called: false}

	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)
	m.Event(nil, nil)
	assert.True(t, mockLogger.Called)
}

// Mock Logger.
type mockLogger struct {
	Called        bool
	CorrelationID string
}

func (l *mockLogger) Log(keyvals ...interface{}) error {
	l.Called = true

	for i, kv := range keyvals {
		if kv == "correlation_id" {
			l.CorrelationID = keyvals[i+1].(string)
		}
	}
	return nil
}
