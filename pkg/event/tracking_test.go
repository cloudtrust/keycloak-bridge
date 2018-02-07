package event

import (
	"context"
	"fmt"
	"testing"
	"time"

	sentry "github.com/getsentry/raven-go"
	"github.com/stretchr/testify/assert"
)

func TestErrorMiddlewareComponents_LoggingErrorMiddleware(t *testing.T) {
	var mockMuxComponent MuxComponent = &mockMuxServiceErr{}
	var calledSentry = false
	var mockSentry Sentry = &mockSentry{Called: calledSentry}

	var m = MakeComponentTrackingMW(mockSentry)(mockMuxComponent)
	m.Event(nil, "test", nil)
	assert.True(t, calledSentry)
}

// Mock Sentry.
type mockSentry struct {
	Called        bool
	CorrelationID string
}

func (client *mockSentry) CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string {
	client.Called = true
	client.CorrelationID = tags["correlation_id"]
	return ""
}

/*
Mock MuxService returning an error for testing Sentry
*/
type mockMuxServiceErr struct{}

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
