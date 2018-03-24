package user

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestNewGRPCServer(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var s = NewGRPCServer(MakeGRPCGetUsersHandler(MakeGetUsersEndpoint(mockComponent)))

	var req = fbUsersRequest("master")
	var names = []string{"john", "jane", "doe"}
	var reply = fbUsersResponse(names)

	// GetUsers.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
	var data, err = s.GetUsers(context.Background(), req)
	assert.Nil(t, err)
	// Decode and check reply.
	var r = fb.GetRootAsGetUsersResponse(data.FinishedBytes(), 0)
	for i := 0; i < r.NamesLength(); i++ {
		assert.Contains(t, names, string(r.Names(i)))
	}
}

func TestGRPCErrorHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var s = NewGRPCServer(MakeGRPCGetUsersHandler(MakeGetUsersEndpoint(mockComponent)))

	var req = fbUsersRequest("master")

	// GetUsers.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(nil, fmt.Errorf("fail")).Times(1)
	var reply, err = s.GetUsers(context.Background(), req)
	assert.NotNil(t, err)
	assert.Nil(t, reply)
}

func TestFetchGRPCCorrelationID(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var s = NewGRPCServer(MakeGRPCGetUsersHandler(MakeGetUsersEndpoint(mockComponent)))

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var md = metadata.New(map[string]string{"correlation_id": corrID})
	var ctx = metadata.NewIncomingContext(context.Background(), md)
	var req = fbUsersRequest("master")
	var names = []string{"john", "jane", "doe"}
	var reply = fbUsersResponse(names)

	// GetUsers.
	mockComponent.EXPECT().GetUsers(context.WithValue(ctx, "correlation_id", corrID), req).Return(reply, nil).Times(1)
	s.GetUsers(ctx, req)

	// GetUsers without correlation ID.
	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(reply, nil).Times(1)
	s.GetUsers(context.Background(), req)
}
