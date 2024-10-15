package account

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"

	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNoRestrictions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockConfigurationDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockAccountComponent = mock.NewComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var credentialID = "786-5684-6464"

	var err error

	// Methods without restrictions allowed anyway
	{
		var authorizationMW = MakeAuthorizationAccountComponentMW(mockLogger, mockConfigurationDBModule)(mockAccountComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		t.Run("GetCredentials", func(t *testing.T) {
			mockAccountComponent.EXPECT().GetCredentials(ctx).Return([]api.CredentialRepresentation{}, nil)
			_, err = authorizationMW.GetCredentials(ctx)
			assert.Nil(t, err)
		})

		t.Run("GetCredentialRegistrators", func(t *testing.T) {
			mockAccountComponent.EXPECT().GetCredentialRegistrators(ctx).Return([]string{}, nil)
			_, err = authorizationMW.GetCredentialRegistrators(ctx)
			assert.Nil(t, err)
		})

		t.Run("UpdateLabelCredential", func(t *testing.T) {
			mockAccountComponent.EXPECT().UpdateLabelCredential(ctx, credentialID, "newLabel").Return(nil)
			err = authorizationMW.UpdateLabelCredential(ctx, credentialID, "newLabel")
			assert.Nil(t, err)
		})

		t.Run("MoveCredential", func(t *testing.T) {
			mockAccountComponent.EXPECT().MoveCredential(ctx, credentialID, credentialID).Return(nil)
			err = authorizationMW.MoveCredential(ctx, credentialID, credentialID)
			assert.Nil(t, err)
		})

		t.Run("GetAccount", func(t *testing.T) {
			mockAccountComponent.EXPECT().GetAccount(ctx).Return(api.AccountRepresentation{}, nil)
			_, err = authorizationMW.GetAccount(ctx)
			assert.Nil(t, err)
		})

		t.Run("GetConfiguration", func(t *testing.T) {
			mockAccountComponent.EXPECT().GetConfiguration(ctx, "").Return(api.Configuration{}, nil)
			_, err = authorizationMW.GetConfiguration(ctx, "")
			assert.Nil(t, err)
		})

		t.Run("GetProfile", func(t *testing.T) {
			mockAccountComponent.EXPECT().GetUserProfile(ctx).Return(apicommon.ProfileRepresentation{}, nil)
			_, err = authorizationMW.GetUserProfile(ctx)
			assert.Nil(t, err)
		})

		t.Run("SendVerifyEmail", func(t *testing.T) {
			mockAccountComponent.EXPECT().SendVerifyEmail(ctx).Return(nil)
			err = authorizationMW.SendVerifyEmail(ctx)
			assert.Nil(t, err)
		})

		t.Run("SendVerifyPhoneNumber", func(t *testing.T) {
			mockAccountComponent.EXPECT().SendVerifyPhoneNumber(ctx).Return(nil)
			err = authorizationMW.SendVerifyPhoneNumber(ctx)
			assert.Nil(t, err)
		})
	}
}

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockConfigurationDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockAccountComponent = mock.NewComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"

	var falseBool = false
	var credentialID = "786-5684-6464"

	var realmConfig = configuration.RealmConfiguration{
		DefaultClientID:                     new(string),
		DefaultRedirectURI:                  new(string),
		APISelfAuthenticatorDeletionEnabled: &falseBool,
		APISelfAccountEditingEnabled:        &falseBool,
		APISelfAccountDeletionEnabled:       &falseBool,
		APISelfPasswordChangeEnabled:        &falseBool,
	}

	var authorizationMW = MakeAuthorizationAccountComponentMW(mockLogger, mockConfigurationDBModule)(mockAccountComponent)
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	var err error

	mockConfigurationDBModule.EXPECT().GetConfiguration(gomock.Any(), realmName).Return(realmConfig, nil).AnyTimes()

	t.Run("UpdatePassword not allowed", func(t *testing.T) {
		err = authorizationMW.UpdatePassword(ctx, "currentPassword", "newPassword", "newPAssword")
		assert.Equal(t, security.ForbiddenError{}, err)
	})
	t.Run("DeleteCredential not allowed", func(t *testing.T) {
		err = authorizationMW.DeleteCredential(ctx, credentialID)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
	t.Run("UpdateAccount - Edition deactivated", func(t *testing.T) {
		err = authorizationMW.UpdateAccount(ctx, api.UpdatableAccountRepresentation{})
		assert.Equal(t, security.ForbiddenError{}, err)
	})
	t.Run("DeleteAccount not allowed", func(t *testing.T) {
		err = authorizationMW.DeleteAccount(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockConfigurationDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockAccountComponent = mock.NewComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"

	var trueBool = true
	var credentialID = "786-5684-6464"

	var realmConfig = configuration.RealmConfiguration{
		DefaultClientID:                     new(string),
		DefaultRedirectURI:                  new(string),
		APISelfAuthenticatorDeletionEnabled: &trueBool,
		APISelfAccountEditingEnabled:        &trueBool,
		APISelfAccountDeletionEnabled:       &trueBool,
		APISelfPasswordChangeEnabled:        &trueBool,
	}

	mockConfigurationDBModule.EXPECT().GetConfiguration(gomock.Any(), realmName).Return(realmConfig, nil).AnyTimes()

	var err error

	// everything allowed
	{
		var authorizationMW = MakeAuthorizationAccountComponentMW(mockLogger, mockConfigurationDBModule)(mockAccountComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		mockAccountComponent.EXPECT().UpdatePassword(ctx, "currentPassword", "newPassword", "newPAssword").Return(nil)
		err = authorizationMW.UpdatePassword(ctx, "currentPassword", "newPassword", "newPAssword")
		assert.Nil(t, err)

		mockAccountComponent.EXPECT().DeleteCredential(ctx, credentialID).Return(nil)
		err = authorizationMW.DeleteCredential(ctx, credentialID)
		assert.Nil(t, err)

		mockAccountComponent.EXPECT().UpdateAccount(ctx, api.UpdatableAccountRepresentation{}).Return(nil)
		err = authorizationMW.UpdateAccount(ctx, api.UpdatableAccountRepresentation{})
		assert.Nil(t, err)

		mockAccountComponent.EXPECT().DeleteAccount(ctx).Return(nil)
		err = authorizationMW.DeleteAccount(ctx)
		assert.Nil(t, err)

	}
}

func TestError(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockConfigurationDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockAccountComponent = mock.NewComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"

	var credentialID = "786-5684-6464"

	var realmConfig = configuration.RealmConfiguration{}

	mockConfigurationDBModule.EXPECT().GetConfiguration(gomock.Any(), realmName).Return(realmConfig, errors.New("unexpected error")).AnyTimes()

	var err error

	// Deny by default in case of error
	{
		var authorizationMW = MakeAuthorizationAccountComponentMW(mockLogger, mockConfigurationDBModule)(mockAccountComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

		err = authorizationMW.UpdatePassword(ctx, "currentPassword", "newPassword", "newPAssword")
		assert.NotNil(t, err)

		err = authorizationMW.DeleteCredential(ctx, credentialID)
		assert.NotNil(t, err)

		err = authorizationMW.UpdateAccount(ctx, api.UpdatableAccountRepresentation{})
		assert.NotNil(t, err)

		err = authorizationMW.DeleteAccount(ctx)
		assert.NotNil(t, err)
	}
}
