package event

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	sentry "github.com/getsentry/raven-go"
	"github.com/stretchr/testify/assert"
)

func TestComponentTrackingMW(t *testing.T) {
	var mockSentry = &mockSentry{}

	var m = MakeComponentTrackingMW(mockSentry)(&mockMuxComponent{fail: true})

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockSentry.Called = false
	mockSentry.CorrelationID = ""
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockSentry.Called)
	assert.Equal(t, id, mockSentry.CorrelationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
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
