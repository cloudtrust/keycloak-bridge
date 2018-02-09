package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponentInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockMuxComponent = &mockMuxComponent{}
	var m = MakeMuxComponentInstrumentingMW(mockHistogram)(mockMuxComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestComponentInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockComponent = &mockComponent{}
	var m = MakeComponentInstrumentingMW(mockHistogram)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	m.Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.Event(context.Background(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestAdminComponentInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockAdminComponent = &mockAdminComponent{}
	var m = MakeAdminComponentInstrumentingMW(mockHistogram)(mockAdminComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	var uid = rand.Int63()
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	m.AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid))
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.AdminEvent(context.Background(), createAdminEvent(fb.OperationTypeCREATE, uid))
	}
	assert.Panics(t, f)
}

func TestConsoleModuleInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockConsoleModule = &mockConsoleModule{}
	var m = MakeConsoleModuleInstrumentingMW(mockHistogram)(mockConsoleModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Print.
	var mp = map[string]string{"key": "val"}
	mockHistogram.called = false
	m.Print(ctx, mp)
	assert.True(t, mockHistogram.called)
}

func TestStatisticModuleInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockStatisticModule = &mockStatisticModule{}

	var m = MakeStatisticModuleInstrumentingMW(mockHistogram)(mockStatisticModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Stats.
	var mp = map[string]string{"key": "val"}
	mockHistogram.called = false
	m.Stats(ctx, mp)
	assert.True(t, mockHistogram.called)
}

// Mock histogram.
type mockHistogram struct {
	called        bool
	correlationID string
}

func (h *mockHistogram) With(labelValues ...string) metrics.Histogram {
	for i, kv := range labelValues {
		if kv == "correlation_id" {
			h.correlationID = labelValues[i+1]
		}
	}
	return h
}

func (h *mockHistogram) Observe(value float64) {
	h.called = true
}
