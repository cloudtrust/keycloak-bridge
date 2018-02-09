package user

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestComponentLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockComponent = &mockComponent{}
	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// User.
	mockLogger.called = false
	mockLogger.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// User without correlation ID.
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
}

func TestModuleLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}
	var mockModule = &mockModule{}
	var m = MakeModuleLoggingMW(mockLogger)(mockModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Print.
	mockLogger.called = false
	mockLogger.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// Print without correlation ID.
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
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
