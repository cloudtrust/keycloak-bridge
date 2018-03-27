package event

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestEventEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockMuxComponent = mock.NewMuxComponent(mockCtrl)

	var e = MakeEventEndpoint(mockMuxComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var uid = rand.Int63()
	var req = Request{
		Type:   "Event",
		Object: createEventBytes(fb.EventTypeCLIENT_DELETE, uid, "realm"),
	}

	// Event.
	mockMuxComponent.EXPECT().Event(ctx, req.Type, req.Object).Return(nil).Times(1)
	var rep, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, rep)
}
