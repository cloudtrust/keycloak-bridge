package register

import (
	"context"
	"encoding/json"
	"testing"

	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeRegisterUserEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRegisterComponent := mock.NewComponent(mockCtrl)

	var realm = "master"
	var first = "John"
	var last = "Doe"
	var user = apiregister.User{FirstName: &first, LastName: &last}
	var m = map[string]string{}

	{
		var bytes, _ = json.Marshal(user)
		m["realm"] = realm
		m["body"] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), realm, user).Return("", nil).Times(1)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m["realm"] = realm
		m["body"] = "{"
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
}
