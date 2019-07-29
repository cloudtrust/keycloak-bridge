package event

import (
	"context"
	"encoding/base64"
	"fmt"
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

func TestComponentTrackingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockSentry = mock.NewSentryTracking(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeMuxComponentTrackingMW(mockSentry, mockLogger)(mockMuxComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var uid = rand.Int63()
	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")

	// Event.
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(nil).Times(1)
	m.Event(ctx, "Event", event)

	// Event error.
	var expected = map[string]string{
		"correlation_id": corrID,
		"event_type":     "Event",
		"obj":            base64.StdEncoding.EncodeToString(event),
	}
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(fmt.Errorf("fail")).Times(1)
	mockSentry.EXPECT().CaptureError(gomock.Any(), expected).Return("").Times(1)
	mockLogger.EXPECT().Debug("unit", "Event", "correlation_id", corrID, "event_type", "Event", "obj", gomock.Any(), "error", "fail").Return(nil).Times(1)

	m.Event(ctx, "Event", event)

	// Event without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), "Event", event).Return(fmt.Errorf("fail")).Times(1)
	var f = func() {
		m.Event(context.Background(), "Event", event)
	}
	assert.Panics(t, f)
}
