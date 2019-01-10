package event

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
)

func TestMuxComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeMuxComponentTracingMW(mockTracer)(mockMuxComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var uid = rand.Int63()
	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")

	// Event.
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", event).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("mux_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, "Event", event)

	// Event error.
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", event).Return(fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("mux_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, "Event", event)

	// Event without tracer.
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", event).Return(nil).Times(1)
	m.Event(context.Background(), "Event", event)

	// Event without correlation ID.
	mockTracer.EXPECT().StartSpan("mux_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Event(opentracing.ContextWithSpan(context.Background(), mockSpan), "Event", event)
	}
	assert.Panics(t, f)
}
func TestComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeComponentTracingMW(mockTracer)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var uid = rand.Int63()
	var event = createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")

	// Event.
	mockComponent.EXPECT().Event(gomock.Any(), event).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, event)

	// Event error.
	mockComponent.EXPECT().Event(gomock.Any(), event).Return(fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Event(ctx, event)

	// Event without tracer.
	mockComponent.EXPECT().Event(gomock.Any(), event).Return(nil).Times(1)
	m.Event(context.Background(), event)

	// Event without correlation ID.
	mockTracer.EXPECT().StartSpan("event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.Event(opentracing.ContextWithSpan(context.Background(), mockSpan), event)
	}
	assert.Panics(t, f)
}

func TestAdminComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeAdminComponentTracingMW(mockTracer)(mockAdminComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var uid = rand.Int63()
	var event = createAdminEvent(fb.OperationTypeCREATE, uid)

	// AdminEvent.
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), event).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("admin_event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.AdminEvent(ctx, event)

	// AdminEvent error.
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), event).Return(fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("admin_event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.AdminEvent(ctx, event)

	// AdminEvent without tracer.
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), event).Return(nil).Times(1)
	m.AdminEvent(context.Background(), event)

	// AdminEvent without correlation ID.
	mockTracer.EXPECT().StartSpan("admin_event_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.AdminEvent(opentracing.ContextWithSpan(context.Background(), mockSpan), event)
	}
	assert.Panics(t, f)
}

func TestConsoleModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeConsoleModuleTracingMW(mockTracer)(mockConsoleModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var mp = map[string]interface{}{"key": "val"}

	// Print.
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("console_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Print(ctx, mp)

	// Print error.
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(fmt.Errorf("fail")).Times(1)
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
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeStatisticModuleTracingMW(mockTracer)(mockStatisticModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var mp = map[string]interface{}{"key": "val"}

	// Stats.
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("statistic_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.Stats(ctx, mp)

	// Stats.
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(fmt.Errorf("fail")).Times(1)
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
