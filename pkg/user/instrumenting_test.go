package user

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/stretchr/testify/assert"
)

func TestComponentInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockComponent = &mockComponent{}
	var m = MakeComponentInstrumentingMW(mockHistogram)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Event.
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
}

func TestModuleInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}
	var mockModule = &mockModule{}

	var m = MakeModuleInstrumentingMW(mockHistogram)(mockModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	// Stats.
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
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
