package user

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestComponentTrackingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockSentry = mock.NewSentry(mockCtrl)

	var m = MakeComponentTrackingMW(mockSentry)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var req = fbUsersRequest("realm")
	var reply = fbUsersResponse([]string{"john", "jane", "doe"})

	// GetUsers.
	mockComponent.EXPECT().GetUsers(ctx, req).Return(reply, nil).Times(1)
	m.GetUsers(ctx, req)

	// GetUsers error.
	mockComponent.EXPECT().GetUsers(ctx, req).Return(nil, fmt.Errorf("fail")).Times(1)
	mockSentry.EXPECT().CaptureError(fmt.Errorf("fail"), map[string]string{"correlation_id": corrID}).Return("").Times(1)
	m.GetUsers(ctx, req)

	// GetUsers without correlation ID.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(nil, fmt.Errorf("fail")).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), req)
	}
	assert.Panics(t, f)
}
