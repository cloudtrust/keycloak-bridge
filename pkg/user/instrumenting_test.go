package user

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeComponentInstrumentingMW(mockHistogram)(mockComponent)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)

	var req = fbUsersRequest("realm")
	var names = []string{"john", "jane", "doe"}
	// User.
	mockComponent.EXPECT().GetUsers(ctx, req).Return(fbUsersResponse(names), nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.GetUsers(ctx, req)

	// User without correlation ID.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(fbUsersResponse(names), nil).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), req)
	}
	assert.Panics(t, f)
}

func TestModuleInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockModule = mock.NewModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeModuleInstrumentingMW(mockHistogram)(mockModule)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)

	// User.
	var names = []string{"john", "jane", "doe"}
	mockModule.EXPECT().GetUsers(ctx, "realm").Return(names, nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.GetUsers(ctx, "realm")

	// User without correlation ID.
	mockModule.EXPECT().GetUsers(context.Background(), "realm").Return(names, nil).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
}
