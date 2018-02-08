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
	mockLogger.Called = false
	mockLogger.CorrelationID = ""
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockLogger.Called)
	assert.Equal(t, id, mockLogger.CorrelationID)

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
	mockLogger.Called = false
	mockLogger.CorrelationID = ""
	m.Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	assert.True(t, mockLogger.Called)
	assert.Equal(t, id, mockLogger.CorrelationID)

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
	mockLogger.Called = false
	mockLogger.CorrelationID = ""
	m.AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid))
	assert.True(t, mockLogger.Called)
	assert.Equal(t, id, mockLogger.CorrelationID)

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
	mockLogger.Called = false
	mockLogger.CorrelationID = ""
	m.Print(ctx, mp)
	assert.True(t, mockLogger.Called)
	assert.Equal(t, id, mockLogger.CorrelationID)

	// Print without correlation ID.
	var f = func() {
		m.Print(context.Background(), mp)
	}
	assert.Panics(t, f)
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
	mockLogger.Called = false
	mockLogger.CorrelationID = ""
	m.Stats(ctx, mp)
	assert.True(t, mockLogger.Called)
	assert.Equal(t, id, mockLogger.CorrelationID)

	// Print without correlation ID.
	var f = func() {
		m.Stats(context.Background(), mp)
	}
	assert.Panics(t, f)
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
