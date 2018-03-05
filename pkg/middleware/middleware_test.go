package middleware

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/event"
	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	fb_flaki "github.com/cloudtrust/keycloak-bridge/pkg/flaki/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/middleware/mock"
	"github.com/golang/mock/gomock"
	flatbuffers "github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
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
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Context with correlation ID.
	mockHealthComponent.EXPECT().InfluxHealthChecks(ctx).Return(health.Reports{}).Times(1)
	m(ctx, nil)

	// Without correlation ID.
	var b = flatbuffers.NewBuilder(0)
	var idStr = b.CreateString(flakiID)
	fb_flaki.FlakiReplyStart(b)
	fb_flaki.FlakiReplyAddId(b, idStr)
	b.Finish(fb_flaki.FlakiReplyEnd(b))
	var reply = fb_flaki.GetRootAsFlakiReply(b.FinishedBytes(), 0)

	mockFlakiClient.EXPECT().NextValidID(gomock.Any(), gomock.Any()).Return(reply, nil).Times(1)
	mockHealthComponent.EXPECT().InfluxHealthChecks(gomock.Any()).Return(health.Reports{}).Times(1)
	mockTracer.EXPECT().StartSpan("get_correlation_id", gomock.Any()).Return(mockSpan).Times(1)
	mockTracer.EXPECT().Inject(gomock.Any(), opentracing.TextMap, gomock.Any())
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(2)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	m(opentracing.ContextWithSpan(context.Background(), mockSpan), nil)
}

func TestEndpointLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)

	var m = MakeEndpointLoggingMW(mockLogger)(event.MakeEventEndpoint(mockMuxComponent))

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var uid = rand.Int63()
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// With correlation ID.
	var req = event.EventRequest{
		Type:   "Event",
		Object: createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"),
	}
	mockLogger.EXPECT().Log("correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	mockMuxComponent.EXPECT().Event(ctx, req.Type, req.Object).Return(nil).Times(1)
	m(ctx, req)

	// Without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), req.Type, req.Object).Return(nil).Times(1)
	var f = func() {
		m(context.Background(), req)
	}
	assert.Panics(t, f)
}

func TestEndpointInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockHistogram = mock.NewHistogram(mockCtrl)
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)

	var m = MakeEndpointInstrumentingMW(mockHistogram)(event.MakeEventEndpoint(mockMuxComponent))

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var uid = rand.Int63()
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// With correlation ID.
	var req = event.EventRequest{
		Type:   "Event",
		Object: createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"),
	}
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	mockMuxComponent.EXPECT().Event(ctx, req.Type, req.Object).Return(nil).Times(1)
	m(ctx, req)

	// Without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), req.Type, req.Object).Return(nil).Times(1)
	var f = func() {
		m(context.Background(), req)
	}
	assert.Panics(t, f)
}

func TestEndpointTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeEndpointTracingMW(mockTracer, "operationName")(event.MakeEventEndpoint(mockMuxComponent))

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var uid = rand.Int63()
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// With correlation ID.
	var req = event.EventRequest{
		Type:   "Event",
		Object: createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"),
	}
	mockTracer.EXPECT().StartSpan("operationName", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag(TracingCorrelationIDKey, corrID).Return(mockSpan).Times(1)
	mockMuxComponent.EXPECT().Event(gomock.Any(), req.Type, req.Object).Return(nil).Times(1)
	m(ctx, req)

	// Without tracer.
	mockMuxComponent.EXPECT().Event(gomock.Any(), req.Type, req.Object).Return(nil).Times(1)
	m(context.Background(), req)

	// Stats without correlation ID.
	mockTracer.EXPECT().StartSpan("operationName", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m(opentracing.ContextWithSpan(context.Background(), mockSpan), req)
	}
	assert.Panics(t, f)
}

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
