package event

import (
	"context"
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
	mockSentry.called = false
	mockSentry.correlationID = ""
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockSentry.called)
	assert.Equal(t, id, mockSentry.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}

// Mock Sentry.
type mockSentry struct {
	called        bool
	correlationID string
}

func (client *mockSentry) CaptureError(err error, tags map[string]string, interfaces ...sentry.Interface) string {
	client.called = true
	client.correlationID = tags["correlation_id"]
	return ""
}
