package user

//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram

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

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var req = fbUsersRequest("realm")
	var reply = fbUsersResponse([]string{"john", "jane", "doe"})

	// GetUsers.
	mockComponent.EXPECT().GetUsers(ctx, req).Return(reply, nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.GetUsers(ctx, req)

	// GetUsers without correlation ID.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
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

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var names = []string{"john", "jane", "doe"}

	// GetUsers.
	mockModule.EXPECT().GetUsers(ctx, "realm").Return(names, nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.GetUsers(ctx, "realm")

	// GetUsers without correlation ID.
	mockModule.EXPECT().GetUsers(context.Background(), "realm").Return(names, nil).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
}
