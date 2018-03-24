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
	"github.com/stretchr/testify/assert"
)

func TestComponentTrackingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)
	var mockSentry = mock.NewSentry(mockCtrl)

	var m = MakeComponentTrackingMW(mockSentry)(mockMuxComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var uid = rand.Int63()
	var event = createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm")

	// Event.
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(nil).Times(1)
	m.Event(ctx, "Event", event)

	// Event error.
	mockMuxComponent.EXPECT().Event(ctx, "Event", event).Return(fmt.Errorf("fail")).Times(1)
	mockSentry.EXPECT().CaptureError(fmt.Errorf("fail"), map[string]string{"correlation_id": corrID}).Return("").Times(1)
	m.Event(ctx, "Event", event)

	// Event without correlation ID.
	mockMuxComponent.EXPECT().Event(context.Background(), "Event", event).Return(fmt.Errorf("fail")).Times(1)
	var f = func() {
		m.Event(context.Background(), "Event", event)
	}
	assert.Panics(t, f)
}
