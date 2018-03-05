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
	"github.com/stretchr/testify/assert"
)

func TestMuxComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeMuxComponentInstrumentingMW(mockHistogram)(mockMuxComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// Event.
	var uid = rand.Int63()
	mockMuxComponent.EXPECT().Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")).Return(nil).Times(1)
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Event(ctx, "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))

	// Event without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), "Event", createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeComponentInstrumentingMW(mockHistogram)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// Event.
	var uid = rand.Int63()
	mockComponent.EXPECT().Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")).Return(nil).Times(1)
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Event(ctx, createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))

	// Event without correlation ID.
	mockComponent.EXPECT().Event(context.Background(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), createEvent(fb.EventTypeCLIENT_INFO, uid, "realm"))
	}
	assert.Panics(t, f)
}

func TestAdminComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeAdminComponentInstrumentingMW(mockHistogram)(mockAdminComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// Event.
	var uid = rand.Int63()
	mockAdminComponent.EXPECT().AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid)).Return(nil).Times(1)
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.AdminEvent(ctx, createAdminEvent(fb.OperationTypeCREATE, uid))

	// Event without correlation ID.
	mockAdminComponent.EXPECT().AdminEvent(context.Background(), createAdminEvent(fb.OperationTypeCREATE, uid)).Return(nil).Times(1)
	var f = func() {
		m.AdminEvent(context.Background(), createAdminEvent(fb.OperationTypeCREATE, uid))
	}
	assert.Panics(t, f)
}

func TestConsoleModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeConsoleModuleInstrumentingMW(mockHistogram)(mockConsoleModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// Print.
	var mp = map[string]string{"key": "val"}
	mockConsoleModule.EXPECT().Print(ctx, mp).Return(nil).Times(1)
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Print(ctx, mp)
}

func TestStatisticModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeStatisticModuleInstrumentingMW(mockHistogram)(mockStatisticModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)

	// Stats.
	var mp = map[string]string{"key": "val"}
	mockStatisticModule.EXPECT().Stats(ctx, mp).Return(nil).Times(1)
	mockHistogram.EXPECT().With(MetricCorrelationIDKey, corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Stats(ctx, mp)
}
