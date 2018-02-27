package middleware

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	fb_flaki "github.com/cloudtrust/keycloak-bridge/pkg/flaki/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	flatbuffers "github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
)

func TestEndpointCorrelationIDMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockHealthComponent = mock.NewHealthComponent(mockCtrl)
	var mockFlakiClient = mock.NewFlakiClient(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeEndpointCorrelationIDMW(mockFlakiClient, mockTracer)(health.MakeInfluxHealthCheckEndpoint(mockHealthComponent))

	rand.Seed(time.Now().UnixNano())
	var flakiID = strconv.FormatUint(rand.Uint64(), 10)
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Context with correlation ID.
	mockHealthComponent.EXPECT().InfluxHealthChecks(ctx).Return(health.HealthReports{}).Times(1)
	m(ctx, nil)

	// Without correlation ID.
	var b = flatbuffers.NewBuilder(0)
	var idStr = b.CreateString(flakiID)
	fb_flaki.FlakiReplyStart(b)
	fb_flaki.FlakiReplyAddId(b, idStr)
	b.Finish(fb_flaki.FlakiReplyEnd(b))
	var reply = fb_flaki.GetRootAsFlakiReply(b.FinishedBytes(), 0)

	mockFlakiClient.EXPECT().NextValidID(gomock.Any(), gomock.Any()).Return(reply, nil).Times(1)
	mockHealthComponent.EXPECT().InfluxHealthChecks(gomock.Any()).Return(health.HealthReports{}).Times(1)
	mockTracer.EXPECT().StartSpan("get_correlation_id", gomock.Any()).Return(mockSpan).Times(1)
	mockTracer.EXPECT().Inject(gomock.Any(), opentracing.TextMap, gomock.Any())
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(2)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	m(opentracing.ContextWithSpan(context.Background(), mockSpan), nil)
}

/*
func TestEndpointLoggingMW(t *testing.T) {
	var mockLogger = &mockLogger{}

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	var endpoints = event.NewEndpoints(MakeEndpointLoggingMW(mockLogger))

	// Event.
	var uid = rand.Int63()
	endpoints = endpoints.MakeKeycloakEndpoint(&mockMuxComponent{fail: false})
	mockLogger.called = false
	mockLogger.correlationID = ""
	endpoints.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockLogger.called)
	assert.Equal(t, id, mockLogger.correlationID)

	// Event without correlation ID.
	var f = func() {
		endpoints.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)

}

func TestEndpointInstrumentingMW(t *testing.T) {
	var mockHistogram = &mockHistogram{}

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)

	var endpoints = event.NewEndpoints(MakeEndpointInstrumentingMW(mockHistogram))

	// Event.
	var uid = rand.Int63()
	endpoints = endpoints.MakeKeycloakEndpoint(&mockMuxComponent{fail: false})
	mockHistogram.called = false
	mockHistogram.correlationID = ""
	endpoints.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockHistogram.called)
	assert.Equal(t, id, mockHistogram.correlationID)

	// Event without correlation ID.
	var f = func() {
		endpoints.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestEndpointTracingMW(t *testing.T) {
	var mockSpan = &mockSpan{}
	var mockTracer = &mockTracer{span: mockSpan}

	// Context with correlation ID and span.
	rand.Seed(time.Now().UnixNano())
	var id = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", id)
	ctx = opentracing.ContextWithSpan(ctx, mockTracer.StartSpan("keycloak"))

	var endpoints = event.NewEndpoints(MakeEndpointTracingMW(mockTracer, "keycloak"))

	// Event.
	var uid = rand.Int63()
	endpoints = endpoints.MakeKeycloakEndpoint(&mockMuxComponent{fail: false})
	mockTracer.called = false
	endpoints.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	assert.True(t, mockTracer.called)
	assert.Equal(t, id, mockTracer.span.correlationID)

	// Event without correlation ID.
	var f = func() {
		endpoints.Event(opentracing.ContextWithSpan(context.Background(), mockTracer.StartSpan("keycloak")), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}
*/
func createEventBytes(eventType int8, uid int64, realm string) []byte {
	var builder = flatbuffers.NewBuilder(0)
	var realmStr = builder.CreateString(realm)
	fb.EventStart(builder)
	fb.EventAddUid(builder, uid)
	fb.EventAddTime(builder, time.Now().Unix())
	fb.EventAddType(builder, eventType)
	fb.EventAddRealmId(builder, realmStr)
	var eventOffset = fb.EventEnd(builder)
	builder.Finish(eventOffset)
	return builder.FinishedBytes()
}
