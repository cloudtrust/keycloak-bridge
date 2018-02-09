package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponentLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockMuxComponent = &mockMuxComponent{}
	var m = MakeMuxComponentLoggingMW(mockLogger)(mockMuxComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockLogger.called = false
	mockLogger.correlationID = ""
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestComponentLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockComponent = &mockComponent{}
	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockLogger.called = false
	mockLogger.correlationID = ""
	m.Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestAdminComponentLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockAdminComponent = &mockAdminComponent{}
	var m = MakeAdminComponentLoggingMW(mockLogger)(mockAdminComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockLogger.called = false
	mockLogger.correlationID = ""
	m.AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid))
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.AdminEvent(context.Background(), createAdminEvent(fb.OperationTypeCREATE, uid))
	}
	assert.Panics(t, f)
}

func TestConsoleModuleLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockConsoleModule = &mockConsoleModule{}
	var m = MakeConsoleModuleLoggingMW(mockLogger)(mockConsoleModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Print.
	var mp = map[string]string{"key": "val"}
	mockLogger.called = false
	m.Print(ctx, mp)
	assert.True(t, mockLogger.called)
}

func TestStatisticModuleLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockStatisticModule = &mockStatisticModule{}

	var m = MakeStatisticModuleLoggingMW(mockLogger)(mockStatisticModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Stats.
	var mp = map[string]string{"key": "val"}
	mockLogger.called = false
	m.Stats(ctx, mp)
	assert.True(t, mockLogger.called)
}

// Mock Logger.
type mockLogger struct {
	called        bool
	correlationID string
}

func (l *mockLogger) Log(keyvals ...interface{}) error {
	l.called = true

	for i, kv := range keyvals {
		if kv == "correlation_id" {
			l.correlationID = keyvals[i+1].(string)
		}
	}
	return nil
}
