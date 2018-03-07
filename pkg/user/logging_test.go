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

func TestComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)
	var req = fbUsersRequest("realm")
	var reply = fbUsersResponse([]string{"john", "jane", "doe"})

	// GetUsers.
	mockComponent.EXPECT().GetUsers(ctx, req).Return(reply, nil).Times(1)
	mockLogger.EXPECT().Log("unit", "user", "realm", string(req.Realm()), LoggingCorrelationIDKey, corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.GetUsers(ctx, req)

	// GetUsers without correlation ID.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), req)
	}
	assert.Panics(t, f)
}

func TestModuleLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockModule = mock.NewModule(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeModuleLoggingMW(mockLogger)(mockModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)
	var names = []string{"john", "jane", "doe"}

	// User.
	mockModule.EXPECT().GetUsers(ctx, "realm").Return(names, nil).Times(1)
	mockLogger.EXPECT().Log("unit", "user", "realm", "realm", CorrelationIDKey, corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.GetUsers(ctx, "realm")

	// User without correlation ID.
	mockModule.EXPECT().GetUsers(context.Background(), "realm").Return(names, nil).Times(1)
	var f = func() {
		m.GetUsers(context.Background(), "realm")
	}
	assert.Panics(t, f)
}
