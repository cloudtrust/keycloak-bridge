package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
)

func TestMuxComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeMuxComponentTracingMW(mockTracer)(mockMuxComponent)
	//ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	//var uid = rand.Int63()
	//var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")
	var corrID = "123-456-789"
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)

	// Event / Spawn
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", gomock.Any()).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "mux_component", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.Event(ctx, "Event", []byte{})

	// Event / Not spawn
	mockMuxComponent.EXPECT().Event(gomock.Any(), "Event", gomock.Any()).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "mux_component", "correlation_id", corrID).Return(ctx, nil).Times(1)
	mockFinisher.EXPECT().Finish().Times(0)
	m.Event(ctx, "Event", []byte{})
}

func TestComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeComponentTracingMW(mockTracer)(mockComponent)
	//ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	//var uid = rand.Int63()
	//var event = createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")
	var corrID = "456-789-123"
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)

	// Event.
	mockComponent.EXPECT().Event(gomock.Any(), gomock.Any()).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "event_component", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.Event(ctx, &fb.Event{})
}

func TestAdminComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeAdminComponentTracingMW(mockTracer)(mockAdminComponent)

	//ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	//var uid = rand.Int63()
	//var event = createAdminEvent(fb.OperationTypeCREATE, uid)
	var corrID = "789-123-456"
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var event = &fb.AdminEvent{}

	// Spawn
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), event).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "admin_event_component", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.AdminEvent(ctx, event)

	// Not spawn
	mockAdminComponent.EXPECT().AdminEvent(gomock.Any(), event).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "admin_event_component", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.AdminEvent(ctx, event)
}

func TestConsoleModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeConsoleModuleTracingMW(mockTracer)(mockConsoleModule)

	//ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var corrID = "987-654-321"
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Spawn
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "console_module", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.Print(ctx, mp)

	// Not spawn
	mockConsoleModule.EXPECT().Print(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "console_module", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.Print(ctx, mp)
}

func TestStatisticModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeStatisticModuleTracingMW(mockTracer)(mockStatisticModule)
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	//ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Spawn
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "statistic_module", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.Stats(ctx, mp)

	// Not spawn
	mockStatisticModule.EXPECT().Stats(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "statistic_module", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.Stats(ctx, mp)
}

func TestEventsDBModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockEventsDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeEventsDBModuleTracingMW(mockTracer)(mockEventsDBModule)
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Spawn
	mockEventsDBModule.EXPECT().Store(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "eventsDB_module", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.Store(ctx, mp)

	// Not spawn
	mockEventsDBModule.EXPECT().Store(gomock.Any(), mp).Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "eventsDB_module", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.Store(ctx, mp)
}
