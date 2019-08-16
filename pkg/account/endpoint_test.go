package account

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeUpdatePasswordEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdatePassword(gomock.Any(), "password", "password2", "password2").Return(nil).Times(1)

	m := map[string]string{}

	{
		m["body"] = "{ \"currentPassword\":\"password\", \"newPassword\":\"password2\", \"confirmPassword\":\"password2\"}"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m["body"] = "{"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
}

func TestMakeGetAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetAccount(gomock.Any()).Return(api.AccountRepresentation{}, nil).Times(1)

	{
		_, err := MakeGetAccountEndpoint(mockAccountComponent)(context.Background(), nil)
		assert.Nil(t, err)
	}
}

func TestMakeUpdateAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateAccount(gomock.Any(), api.AccountRepresentation{}).Return(nil).Times(1)

	m := map[string]string{}

	{
		m["body"] = "{}"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m["body"] = `{ "email": "" }`
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

	{
		m["body"] = "{"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
}
