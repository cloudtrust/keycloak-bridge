package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
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

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")

	// Event.
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Event(ctx, "Event", event)

	// Event without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), "Event", event).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), "Event", event)
	}
	assert.Panics(t, f)
}

func TestComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeComponentInstrumentingMW(mockHistogram)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")

	// Event.
	mockComponent.EXPECT().Event(ctx, event).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Event(ctx, event)

	// Event without correlation ID.
	mockComponent.EXPECT().Event(context.Background(), event).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), event)
	}
	assert.Panics(t, f)
}

func TestAdminComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeAdminComponentInstrumentingMW(mockHistogram)(mockAdminComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createAdminEvent(fb.OperationTypeCREATE, uid)

	// Event.
	mockAdminComponent.EXPECT().AdminEvent(ctx, event).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.AdminEvent(ctx, event)

	// Event without correlation ID.
	mockAdminComponent.EXPECT().AdminEvent(context.Background(), event).Return(nil).Times(1)
	var f = func() {
		m.AdminEvent(context.Background(), event)
	}
	assert.Panics(t, f)
}

func TestConsoleModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeConsoleModuleInstrumentingMW(mockHistogram)(mockConsoleModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Print.
	mockConsoleModule.EXPECT().Print(ctx, mp).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Print(ctx, mp)
}

func TestStatisticModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeStatisticModuleInstrumentingMW(mockHistogram)(mockStatisticModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Stats.
	mockStatisticModule.EXPECT().Stats(ctx, mp).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Stats(ctx, mp)
}

func TestEventsDBModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockEventsDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeEventsDBModuleInstrumentingMW(mockHistogram)(mockEventsDBModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Stats.
	mockEventsDBModule.EXPECT().Store(ctx, mp).Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.Store(ctx, mp)
}
