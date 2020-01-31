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
	var user = apiregister.UserRepresentation{FirstName: &first, LastName: &last}
	var m = map[string]string{}

	t.Run("No specified realm", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m["realm"] = ""
		m["body"] = string(bytes)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("Valid request", func(t *testing.T) {
		var bytes, _ = json.Marshal(user)
		m["realm"] = realm
		m["body"] = string(bytes)
		mockRegisterComponent.EXPECT().RegisterUser(gomock.Any(), realm, user).Return("", nil).Times(1)
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("Invalid JSON in body", func(t *testing.T) {
		m["realm"] = realm
		m["body"] = "{"
		_, err := MakeRegisterUserEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
}

func TestMakeGetConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRegisterComponent := mock.NewComponent(mockCtrl)

	t.Run("Missing realm", func(t *testing.T) {
		var m = map[string]string{}
		_, err := MakeGetConfigurationEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var realm = "my-realm"
		var m = map[string]string{"realm": realm}
		mockRegisterComponent.EXPECT().GetConfiguration(gomock.Any(), realm).Return(apiregister.ConfigurationRepresentation{}, nil).Times(1)
		_, err := MakeGetConfigurationEndpoint(mockRegisterComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}
