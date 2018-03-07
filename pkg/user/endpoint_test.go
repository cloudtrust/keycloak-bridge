package user

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetUsersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetUsersEndpoint(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), CorrelationIDKey, corrID)
	var req = fbUsersRequest("master")
	var names = []string{"john", "jane", "doe"}
	var reply = fbUsersResponse(names)

	// GetUsers.
	{
		mockComponent.EXPECT().GetUsers(ctx, req).Return(reply, nil).Times(1)
		var reply, err = e(ctx, req)
		var r = reply.(*fb.GetUsersResponse)
		assert.Nil(t, err)
		assert.Equal(t, len(names), r.NamesLength())
		for i := 0; i < r.NamesLength(); i++ {
			assert.Contains(t, names, string(r.Names(i)))
		}
	}

	// GetUsers error.
	{
		mockComponent.EXPECT().GetUsers(ctx, req).Return(nil, fmt.Errorf("fail")).Times(1)
		var reply, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, reply)
	}

	// Wrong request type.
	{
		var reply, err = e(ctx, nil)
		assert.NotNil(t, err)
		assert.Nil(t, reply)
	}
}
