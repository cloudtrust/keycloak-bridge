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

func TestMuxComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeMuxComponentLoggingMW(mockLogger)(mockMuxComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")

	// Event.
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(nil).Times(1)
	mockLogger.EXPECT().Log("unit", "Event", "type", "Event", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.Event(ctx, "Event", event)

	// Event without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), "Event", event).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), "Event", event)
	}
	assert.Panics(t, f)
}

func TestComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createEvent(fb.EventTypeCLIENT_INFO, uid, "realm")

	// Event.
	mockComponent.EXPECT().Event(ctx, event).Return(nil).Times(1)
	mockLogger.EXPECT().Log("unit", "Event", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.Event(ctx, event)

	// Event without correlation ID.
	mockComponent.EXPECT().Event(context.Background(), event).Return(nil).Times(1)
	var f = func() {
		m.Event(context.Background(), event)
	}
	assert.Panics(t, f)
}

func TestAdminComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockAdminComponent = mock.NewAdminComponent(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeAdminComponentLoggingMW(mockLogger)(mockAdminComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createAdminEvent(fb.OperationTypeCREATE, uid)

	// Event.
	mockAdminComponent.EXPECT().AdminEvent(ctx, event).Return(nil).Times(1)
	mockLogger.EXPECT().Log("unit", "AdminEvent", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.AdminEvent(ctx, event)

	// Event without correlation ID.
	mockAdminComponent.EXPECT().AdminEvent(context.Background(), event).Return(nil).Times(1)
	var f = func() {
		m.AdminEvent(context.Background(), event)
	}
	assert.Panics(t, f)
}

func TestConsoleModuleLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConsoleModule = mock.NewConsoleModule(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeConsoleModuleLoggingMW(mockLogger)(mockConsoleModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Print.
	mockConsoleModule.EXPECT().Print(ctx, mp).Return(nil).Times(1)
	mockLogger.EXPECT().Log("method", "Print", "args", mp, "took", gomock.Any()).Return(nil).Times(1)
	m.Print(ctx, mp)
}

func TestStatisticModuleLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockStatisticModule = mock.NewStatisticModule(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeStatisticModuleLoggingMW(mockLogger)(mockStatisticModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var mp = map[string]string{"key": "val"}

	// Stats.
	mockStatisticModule.EXPECT().Stats(ctx, mp).Return(nil).Times(1)
	mockLogger.EXPECT().Log("method", "Stats", "args", mp, "took", gomock.Any()).Return(nil).Times(1)
	m.Stats(ctx, mp)
}
