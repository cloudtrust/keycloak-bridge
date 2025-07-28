package account

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	logger "github.com/cloudtrust/common-service/v2/log"
	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMakeUpdatePasswordEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdatePassword(gomock.Any(), "password", "password2", "password2").Return(nil)

	t.Run("Success", func(t *testing.T) {
		var m = map[string]string{reqBody: `{"currentPassword":"password", "newPassword":"password2", "confirmPassword":"password2"}`}
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Invalid JSON in body", func(t *testing.T) {
		var m = map[string]string{reqBody: `{`}
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Invalid parameter in body", func(t *testing.T) {
		var m = map[string]string{reqBody: `{"currentPassword":"", "newPassword":"password2", "confirmPassword":"password2"}`}
		_, err := MakeUpdatePasswordEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
}

func TestMakeGetCredentialsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentials(gomock.Any()).Return([]account_api.CredentialRepresentation{}, nil)

	m := map[string]string{}
	_, err := MakeGetCredentialsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetCredentialRegistratorsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetCredentialRegistrators(gomock.Any()).Return([]string{}, nil)

	m := map[string]string{}
	_, err := MakeGetCredentialRegistratorsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateLabelCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().UpdateLabelCredential(gomock.Any(), "id", "label").Return(nil)

	t.Run("Success", func(t *testing.T) {
		var m = map[string]string{reqBody: `{"userLabel":"label"}`, prmCredentialID: `id`}
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("Invalid JSON in body", func(t *testing.T) {
		var m = map[string]string{reqBody: `{`}
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Invalid ID", func(t *testing.T) {
		var m = map[string]string{reqBody: `{"id":"invalid"}`, prmCredentialID: `id`}
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
	t.Run("Missing user label", func(t *testing.T) {
		var m = map[string]string{reqBody: `{"phoneNumber":"label"}`, prmCredentialID: `id`}
		_, err := MakeUpdateLabelCredentialEndpoint(mockAccountComponent)(context.Background(), m)
		assert.NotNil(t, err)
	})
}

func TestMakeDeleteCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().DeleteCredential(gomock.Any(), "id").Return(nil)

	m := map[string]string{}

	m[prmCredentialID] = "id"
	_, err := MakeDeleteCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeMoveCredentialEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().MoveCredential(gomock.Any(), "id1", "id2").Return(nil)

	m := map[string]string{}

	m[prmCredentialID] = "id1"
	m[prmPrevCredentialID] = "id2"
	_, err := MakeMoveCredentialEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeGetAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetAccount(gomock.Any()).Return(account_api.AccountRepresentation{}, nil)

	m := map[string]string{}
	_, err := MakeGetAccountEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeUpdateAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockProfileCache     = mock.NewUserProfileCache(mockCtrl)
		mockAccountComponent = mock.NewComponent(mockCtrl)
		endpoint             = MakeUpdateAccountEndpoint(mockAccountComponent, mockProfileCache, logger.NewNopLogger())

		realm   = "the-realm"
		ctx     = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
		profile = kc.UserProfileRepresentation{
			Attributes: []kc.ProfileAttrbRepresentation{
				{
					Name:        ptr("phoneNumber"),
					Annotations: map[string]string{apiName: "true"},
					Validations: kc.ProfileAttrbValidationRepresentation{
						"pattern": kc.ProfileAttrValidatorRepresentation{"pattern": `^\+\d+$`},
					},
				},
			},
		}
	)

	t.Run("Valid JSON body", func(t *testing.T) {
		m := map[string]string{reqBody: `{ "phoneNumber": "+41767815784"}`}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(profile, nil)
		mockAccountComponent.EXPECT().UpdateAccount(gomock.Any(), gomock.Any()).Return(nil)
		_, err := endpoint(ctx, m)
		assert.Nil(t, err)
	})
	t.Run("Invalid JSON body", func(t *testing.T) {
		m := map[string]string{reqBody: "{"}
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})
	t.Run("Invalid body content", func(t *testing.T) {
		m := map[string]string{reqBody: `{ "phoneNumber": "ABCD"}`}
		mockProfileCache.EXPECT().GetRealmUserProfile(ctx, realm).Return(profile, nil)
		_, err := endpoint(ctx, m)
		assert.NotNil(t, err)
	})
}

func TestMakeGetLinkedAccountsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().GetLinkedAccounts(gomock.Any()).Return([]account_api.LinkedAccountRepresentation{}, nil)

	m := map[string]string{}
	_, err := MakeGetLinkedAccountsEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestMakeDeleteLinkedAccountEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockAccountComponent := mock.NewComponent(mockCtrl)
	mockAccountComponent.EXPECT().DeleteLinkedAccount(gomock.Any(), "idp").Return(nil)

	m := map[string]string{}

	m[prmProviderAlias] = "idp"
	_, err := MakeDeleteLinkedAccountEndpoint(mockAccountComponent)(context.Background(), m)
	assert.Nil(t, err)
}

func TestSimpleEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockAccountComponent = mock.NewComponent(mockCtrl)
	var m = map[string]string{}

	t.Run("MakeDeleteAccountEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().DeleteAccount(gomock.Any()).Return(nil)

		var _, err = MakeDeleteAccountEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeGetConfigurationEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().GetConfiguration(gomock.Any(), gomock.Any()).Return(account_api.Configuration{}, nil)
		_, err := MakeGetConfigurationEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
	t.Run("MakeGetProfileEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().GetUserProfile(gomock.Any()).Return(apicommon.ProfileRepresentation{}, nil)
		_, err := MakeGetUserProfileEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeSendVerifyEmailEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().SendVerifyEmail(gomock.Any()).Return(nil)
		_, err := MakeSendVerifyEmailEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeSendVerifyPhoneNumberEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().SendVerifyPhoneNumber(gomock.Any()).Return(nil)
		_, err := MakeSendVerifyPhoneNumberEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeCancelEmailChangeEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().CancelEmailChange(gomock.Any()).Return(nil)
		_, err := MakeCancelEmailChangeEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})

	t.Run("MakeCancelPhoneNumberChangeEndpoint", func(t *testing.T) {
		mockAccountComponent.EXPECT().CancelPhoneNumberChange(gomock.Any()).Return(nil)
		_, err := MakeCancelPhoneNumberChangeEndpoint(mockAccountComponent)(context.Background(), m)
		assert.Nil(t, err)
	})
}
