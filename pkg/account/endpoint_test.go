package account

import (
	"context"
	"testing"

	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
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

func TestMakeGetCredentialsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentials(gomock.Any()).Return([]account_api.CredentialRepresentation{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetCredentialsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetCredentialRegistratorsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentialRegistrators(gomock.Any()).Return([]string{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetCredentialRegistratorsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateLabelCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateLabelCredential(gomock.Any(), "id", "label").Return(nil).Times(1)

	m := map[string]string{}

	{
		m["body"] = "{ \"userLabel\": \"label\"}"
		m["credentialID"] = "id"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m["body"] = "{"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
	{
		m["body"] = "{ \"phoneNumber\": \"label\"}"
		m["credentialID"] = "id"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

}

func TestMakeDeleteCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().DeleteCredential(gomock.Any(), "id").Return(nil).Times(1)

	m := map[string]string{}

	m["credentialID"] = "id"
	_, err := MakeDeleteCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeMoveCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().MoveCredential(gomock.Any(), "id1", "id2").Return(nil).Times(1)

	m := map[string]string{}

	m["credentialID"] = "id1"
	m["previousCredentialID"] = "id2"
	_, err := MakeMoveCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetAccount(gomock.Any()).Return(account_api.AccountRepresentation{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetAccountEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateAccount(gomock.Any(), account_api.AccountRepresentation{}).Return(nil).Times(1)
	{
		m := map[string]string{}
		m["body"] = "{ \"userLabel\": \"label\"}"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}
	{
		m := map[string]string{}
		m["body"] = "{"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
	{
		m := map[string]string{}
		m["body"] = "{\"phoneNumber\": \"label\"}"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

}

func TestMakeDeleteAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().DeleteAccount(gomock.Any()).Return(nil).Times(1)

	m := map[string]string{}
	_, err := MakeDeleteAccountEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetConfigurationEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewAccountComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetConfiguration(gomock.Any()).Return(account_api.Configuration{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetConfigurationEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}
