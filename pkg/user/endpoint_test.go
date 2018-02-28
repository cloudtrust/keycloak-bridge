package user

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeUserEndpoint(mockComponent)

	var req = fbUsersRequest("master")
	var names = []string{"john", "jane", "doe"}

	mockComponent.EXPECT().GetUsers(context.Background(), req).Return(fbUsersResponse(names), nil).Times(1)
	var reply, err = e(context.Background(), req)
	var r = reply.(*fb.GetUsersResponse)
	assert.Nil(t, err)
	assert.Equal(t, len(names), r.NamesLength())

	for i := 0; i < r.NamesLength(); i++ {
		assert.Contains(t, names, string(r.Names(i)))
	}
}
