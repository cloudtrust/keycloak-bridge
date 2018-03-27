package user

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/google/flatbuffers/go"
	"github.com/stretchr/testify/assert"
)

func TestComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockModule = mock.NewModule(mockCtrl)

	var c = NewComponent(mockModule)

	var users = []string{"john", "jane", "doe"}
	var req = fbUsersRequest("master")

	mockModule.EXPECT().GetUsers(context.Background(), "master").Return(users, nil).Times(1)
	var reply, err = c.GetUsers(context.Background(), req)
	assert.Nil(t, err)
	assert.Equal(t, len(users), reply.NamesLength())

	for i := 0; i < reply.NamesLength(); i++ {
		assert.Contains(t, users, string(reply.Names(i)))
	}

	// Module error.
	mockModule.EXPECT().GetUsers(context.Background(), "master").Return(nil, fmt.Errorf("fail")).Times(1)
	reply, err = c.GetUsers(context.Background(), req)
	assert.Nil(t, reply)
	assert.NotNil(t, err)
}

func fbUsersRequest(realm string) *fb.GetUsersRequest {
	var b = flatbuffers.NewBuilder(0)
	var brealm = b.CreateString(realm)
	fb.GetUsersRequestStart(b)
	fb.GetUsersRequestAddRealm(b, brealm)
	b.Finish(fb.GetUsersRequestEnd(b))

	return fb.GetRootAsGetUsersRequest(b.FinishedBytes(), 0)
}
