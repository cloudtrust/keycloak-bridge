package user

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	olog "github.com/opentracing/opentracing-go/log"
	"github.com/stretchr/testify/assert"
)

func TestComponentTracingMW(t *testing.T) {
	var mockSpan = &mockSpan{}
	var mockTracer = &mockTracer{span: mockSpan}
	var mockComponent = &mockComponent{}

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)
	ctx = opentracing.ContextWithSpan(ctx, mockTracer.StartSpan("event"))

	var m = MakeComponentTracingMW(mockTracer)(mockComponent)

	// Event.
	mockTracer.called = false
	mockTracer.span.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockTracer.called)
	assert.Equal(t, id, mockTracer.span.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.GetUsers(opentracing.ContextWithSpan(context.Background(), mockTracer.StartSpan("user")), "realm")
	}
	assert.Panics(t, f)
}

func TestModuleTracingMW(t *testing.T) {
	var mockSpan = &mockSpan{}
	var mockTracer = &mockTracer{span: mockSpan}
	var mockModule = &mockModule{}

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)
	ctx = opentracing.ContextWithSpan(ctx, mockTracer.StartSpan("event"))

	var m = MakeModuleTracingMW(mockTracer)(mockModule)

	// Print.
	mockTracer.called = false
	mockTracer.span.correlationID = ""
	m.GetUsers(ctx, "realm")
	assert.True(t, mockTracer.called)
	assert.Equal(t, id, mockTracer.span.correlationID)

	// Event without correlation ID.
	var f = func() {
		m.GetUsers(opentracing.ContextWithSpan(context.Background(), mockTracer.StartSpan("user")), "realm")
	}
	assert.Panics(t, f)
}

// Mock Tracer.
type mockTracer struct {
	called bool
	span   *mockSpan
}

func (t *mockTracer) StartSpan(operationName string, opts ...opentracing.StartSpanOption) opentracing.Span {
	t.called = true
	return t.span
}
func (t *mockTracer) Inject(sm opentracing.SpanContext, format interface{}, carrier interface{}) error {
	return nil
}
func (t *mockTracer) Extract(format interface{}, carrier interface{}) (opentracing.SpanContext, error) {
	return nil, nil
}

// Mock Span.
type mockSpan struct {
	correlationID string
}

func (s *mockSpan) SetTag(key string, value interface{}) opentracing.Span {
	if key == "correlation_id" {
		s.correlationID = value.(string)
	}
	return s
}
func (s *mockSpan) Finish()                                                     {}
func (s *mockSpan) FinishWithOptions(opts opentracing.FinishOptions)            {}
func (s *mockSpan) Context() opentracing.SpanContext                            { return nil }
func (s *mockSpan) SetOperationName(operationName string) opentracing.Span      { return s }
func (s *mockSpan) LogFields(fields ...olog.Field)                              {}
func (s *mockSpan) LogKV(alternatingKeyValues ...interface{})                   {}
func (s *mockSpan) SetBaggageItem(restrictedKey, value string) opentracing.Span { return s }
func (s *mockSpan) BaggageItem(restrictedKey string) string                     { return "" }
func (s *mockSpan) Tracer() opentracing.Tracer                                  { return nil }
func (s *mockSpan) LogEvent(event string)                                       {}
func (s *mockSpan) LogEventWithPayload(event string, payload interface{})       {}
func (s *mockSpan) Log(data opentracing.LogData)                                {}
