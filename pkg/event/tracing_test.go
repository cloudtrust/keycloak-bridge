package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)

	var m = MakeMuxComponentTracingMW(mockTracer)(mockMuxComponent)

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Event.
	var uid = rand.Int63()
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("mux_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))

	// Event without tracer.
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")).Return(nil).Times(1)
	m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))

	// Event without correlation ID.
	mockTracer.EXPECT().StartSpan("mux_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Event(opentracing.ContextWithSpan(context.Background(), mockSpan), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}
func TestComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockComponent = mock.NewComponent(mockCtrl)

	var m = MakeComponentTracingMW(mockTracer)(mockComponent)

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Event.
	var uid = rand.Int63()
	mockComponent.EXPECT().Event(gomock.Any(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))

	// Event without tracer.
	mockComponent.EXPECT().Event(gomock.Any(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")).Return(nil).Times(1)
	m.Event(context.Background(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))

	// Event without correlation ID.
	mockTracer.EXPECT().StartSpan("event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Event(opentracing.ContextWithSpan(context.Background(), mockSpan), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestAdminComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)

	var m = MakeAdminComponentTracingMW(mockTracer)(mockAdminComponent)

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// AdminEvent.
	var uid = rand.Int63()
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), createAdminEvent(fb.OperationTypeCREATE, uid)).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("admin_event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid))

	// AdminEvent without tracer.
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), createAdminEvent(fb.OperationTypeCREATE, uid)).Return(nil).Times(1)
	m.AdminEvent(context.Background(), createAdminEvent(fb.OperationTypeCREATE, uid))

	// AdminEvent without correlation ID.
	mockTracer.EXPECT().StartSpan("admin_event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.AdminEvent(opentracing.ContextWithSpan(context.Background(), mockSpan), createAdminEvent(fb.OperationTypeCREATE, uid))
	}
	assert.Panics(t, f)
}

func TestConsoleModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)

	var m = MakeConsoleModuleTracingMW(mockTracer)(mockConsoleModule)

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Print.
	var mp = map[string]string{"key": "val"}
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("console_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Print(ctx, mp)

	// Print without tracer.
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(nil).Times(1)
	m.Print(context.Background(), mp)

	// Print without correlation ID.
	mockTracer.EXPECT().StartSpan("console_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Print(opentracing.ContextWithSpan(context.Background(), mockSpan), mp)
	}
	assert.Panics(t, f)
}

func TestStatisticModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)

	var m = MakeStatisticModuleTracingMW(mockTracer)(mockStatisticModule)

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Stats.
	var mp = map[string]string{"key": "val"}
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("statistic_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Stats(ctx, mp)

	// Stats without tracer.
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(nil).Times(1)
	m.Stats(context.Background(), mp)

	// Stats without correlation ID.
	mockTracer.EXPECT().StartSpan("statistic_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Stats(opentracing.ContextWithSpan(context.Background(), mockSpan), mp)
	}
	assert.Panics(t, f)
}
