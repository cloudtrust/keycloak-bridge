package account

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

//go:generate mockgen -destination=./mock/accountcomponent.go -package=mock -mock_names=AccountComponent=AccountComponent github.com/cloudtrust/keycloak-bridge/pkg/account AccountComponent

func TestMakeUpdatePasswordEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdatePassword(gomock.Any(), "", "", "").Return(nil).Times(1)

	m := map[string]string{}

	{
		m["body"] = "{}"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m["body"] = "{"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
}
