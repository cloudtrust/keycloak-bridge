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

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdatePassword(gomock.Any(), "password", "password2", "password2").Return(nil).Times(1)

	m := map[string]string{}

	{
		m[ReqBody] = "{ \"currentPassword\":\"password\", \"newPassword\":\"password2\", \"confirmPassword\":\"password2\"}"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m[ReqBody] = "{"
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

}

func TestMakeGetCredentialsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentials(gomock.Any()).Return([]account_api.CredentialRepresentation{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetCredentialsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetCredentialRegistratorsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentialRegistrators(gomock.Any()).Return([]string{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetCredentialRegistratorsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateLabelCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateLabelCredential(gomock.Any(), "id", "label").Return(nil).Times(1)

	m := map[string]string{}

	{
		m[ReqBody] = "{ \"userLabel\": \"label\"}"
		m[PrmCredentialID] = "id"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}

	{
		m[ReqBody] = "{"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
	{
		m[ReqBody] = "{ \"phoneNumber\": \"label\"}"
		m[PrmCredentialID] = "id"
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

}

func TestMakeDeleteCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().DeleteCredential(gomock.Any(), "id").Return(nil).Times(1)

	m := map[string]string{}

	m[PrmCredentialID] = "id"
	_, err := MakeDeleteCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeMoveCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().MoveCredential(gomock.Any(), "id1", "id2").Return(nil).Times(1)

	m := map[string]string{}

	m[PrmCredentialID] = "id1"
	m[PrmPrevCredentialID] = "id2"
	_, err := MakeMoveCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetAccount(gomock.Any()).Return(account_api.AccountRepresentation{}, nil).Times(1)

	m := map[string]string{}
	_, err := MakeGetAccountEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateAccount(gomock.Any(), account_api.UpdatableAccountRepresentation{}).Return(nil).Times(1)
	{
		m := map[string]string{}
		m[ReqBody] = "{ \"userLabel\": \"label\"}"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	}
	{
		m := map[string]string{}
		m[ReqBody] = "{"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}
	{
		m := map[string]string{}
		m[ReqBody] = "{\"phoneNumber\": \"label\"}"
		_, err := MakeUpdateAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	}

}

func TestSimpleEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockAccountComponent = mock.NewComponent(mockCtrl)
	var m = map[string]string{}

	t.Run("MakeDeleteAccountEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().DeleteAccount(gomock.Any()).Return(nil).Times(1)

		var _, err = MakeDeleteAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeGetConfigurationEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(account_api.Configuration{}, nil).Times(1)
		_, err := MakeGetConfigurationEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeSendVerifyEmailEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().SendVerifyEmail(gomock.Any()).Return(nil).Times(1)
		_, err := MakeSendVerifyEmailEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeSendVerifyPhoneNumberEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().SendVerifyPhoneNumber(gomock.Any()).Return(nil).Times(1)
		_, err := MakeSendVerifyPhoneNumberEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}
