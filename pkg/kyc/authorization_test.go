package kyc

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service"
	logger "github.com/cloudtrust/common-service/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActionsString(t *testing.T) {
	assert.Len(t, GetActions(), len(actions))
}

func TestMakeAuthorizationRegisterComponentMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var mockAuthManager = mock.NewAuthorizationManager(mockCtrl)
	var mockAvailabilityChecker = mock.NewEndpointAvailabilityChecker(mockCtrl)

	var realm = "master"
	var ctx = context.WithValue(context.Background(), cs.CtContextRealm, realm)
	var user = apikyc.UserRepresentation{}
	var userID = "user4673"
	var username = "username"
	var consentCode *string
	var expectedErr = errors.New("")

	var component = MakeAuthorizationRegisterComponentMW(realm, mockAuthManager, mockAvailabilityChecker, logger.NewNopLogger())(mockComponent)

	t.Run("GetActions", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetActions.String(), gomock.Any()).Return(expectedErr)
			var _, err = component.GetActions(ctx)
			assert.Equal(t, expectedErr, err)
		})

		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetActions.String(), gomock.Any()).Return(nil)
			mockComponent.EXPECT().GetActions(ctx).Return([]apikyc.ActionRepresentation{}, expectedErr)
			var _, err = component.GetActions(ctx)
			assert.Equal(t, expectedErr, err)
		})
	})

	t.Run("GetUserInSocialRealm", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetUserInSocialRealm.String(), realm).Return(expectedErr)
			var _, err = component.GetUserInSocialRealm(ctx, userID, consentCode)
			assert.Equal(t, expectedErr, err)
		})

		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetUserInSocialRealm.String(), realm).Return(nil)
			mockComponent.EXPECT().GetUserInSocialRealm(ctx, userID, consentCode).Return(apikyc.UserRepresentation{}, expectedErr)
			var _, err = component.GetUserInSocialRealm(ctx, userID, consentCode)
			assert.Equal(t, expectedErr, err)
		})
	})
	t.Run("GetUser", func(t *testing.T) {
		t.Run("not configured", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, expectedErr)
			var _, err = component.GetUser(ctx, realm, userID, consentCode)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("not authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCGetUser.String(), realm, userID).Return(expectedErr)
			var _, err = component.GetUser(ctx, realm, userID, consentCode)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCGetUser.String(), realm, userID).Return(nil)
			mockComponent.EXPECT().GetUser(ctx, realm, userID, consentCode).Return(apikyc.UserRepresentation{}, expectedErr)
			var _, err = component.GetUser(ctx, realm, userID, consentCode)
			assert.Equal(t, expectedErr, err)
		})
	})

	t.Run("GetUserByUsernameInSocialRealm", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetUserByUsernameInSocialRealm.String(), realm).
				Return(nil).Return(expectedErr)
			var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
			assert.Equal(t, expectedErr, err)
		})

		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetUserByUsernameInSocialRealm.String(), realm).Return(nil)
			mockComponent.EXPECT().GetUserByUsernameInSocialRealm(ctx, username).Return(apikyc.UserRepresentation{}, expectedErr)
			var _, err = component.GetUserByUsernameInSocialRealm(ctx, username)
			assert.Equal(t, expectedErr, err)
		})
	})
	t.Run("GetUserByUsername", func(t *testing.T) {
		t.Run("not configured", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, expectedErr)
			var _, err = component.GetUserByUsername(ctx, realm, username)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("component fails", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockComponent.EXPECT().GetUserByUsername(ctx, realm, username).Return(apikyc.UserRepresentation{}, expectedErr)
			var _, err = component.GetUserByUsername(ctx, realm, username)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("not authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockComponent.EXPECT().GetUserByUsername(ctx, realm, username).Return(apikyc.UserRepresentation{ID: &userID}, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCGetUserByUsername.String(), realm, userID).Return(expectedErr)
			var _, err = component.GetUserByUsername(ctx, realm, username)
			assert.NotNil(t, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockComponent.EXPECT().GetUserByUsername(ctx, realm, username).Return(apikyc.UserRepresentation{ID: &userID}, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCGetUserByUsername.String(), realm, userID).Return(nil)
			var _, err = component.GetUserByUsername(ctx, realm, username)
			assert.Nil(t, err)
		})
	})

	t.Run("ValidateUserInSocialRealm", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCValidateUserInSocialRealm.String(), realm).Return(expectedErr)
			var err = component.ValidateUserInSocialRealm(ctx, userID, user, consentCode)
			assert.Equal(t, expectedErr, err)
		})

		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCValidateUserInSocialRealm.String(), realm).Return(nil)
			mockComponent.EXPECT().ValidateUserInSocialRealm(ctx, userID, user, consentCode).Return(expectedErr)
			var err = component.ValidateUserInSocialRealm(ctx, userID, user, consentCode)
			assert.Equal(t, expectedErr, err)
		})
	})

	t.Run("ValidateUser", func(t *testing.T) {
		t.Run("endpoint not enabled for this realm", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, expectedErr)
			var err = component.ValidateUser(ctx, realm, userID, user, consentCode)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("not authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCValidateUser.String(), realm, userID).Return(expectedErr)
			var err = component.ValidateUser(ctx, realm, userID, user, consentCode)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCValidateUser.String(), realm, userID).Return(nil)
			mockComponent.EXPECT().ValidateUser(ctx, realm, userID, user, consentCode).Return(expectedErr)
			var err = component.ValidateUser(ctx, realm, userID, user, consentCode)
			assert.Equal(t, expectedErr, err)
		})
	})

	t.Run("SendSmsConsentCodeInSocialRealm", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCSendSmsConsentCodeInSocialRealm.String(), realm).Return(expectedErr)
			var err = component.SendSmsConsentCodeInSocialRealm(ctx, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCSendSmsConsentCodeInSocialRealm.String(), realm).Return(nil)
			mockComponent.EXPECT().SendSmsConsentCodeInSocialRealm(ctx, userID).Return(expectedErr)
			var err = component.SendSmsConsentCodeInSocialRealm(ctx, userID)
			assert.Equal(t, expectedErr, err)
		})
	})
	t.Run("SendSmsConsentCode", func(t *testing.T) {
		t.Run("not configured", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, expectedErr)
			var err = component.SendSmsConsentCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("not authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCSendSmsConsentCode.String(), realm, userID).Return(expectedErr)
			var err = component.SendSmsConsentCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCSendSmsConsentCode.String(), realm, userID).Return(nil)
			mockComponent.EXPECT().SendSmsConsentCode(ctx, realm, userID).Return(expectedErr)
			var err = component.SendSmsConsentCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
	})

	t.Run("SendSmsCodeInSocialRealm", func(t *testing.T) {
		t.Run("not authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCSendSmsCodeInSocialRealm.String(), realm).Return(expectedErr)
			var _, err = component.SendSmsCodeInSocialRealm(ctx, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCSendSmsCodeInSocialRealm.String(), realm).Return(nil)
			mockComponent.EXPECT().SendSmsCodeInSocialRealm(ctx, userID).Return("", expectedErr)
			var _, err = component.SendSmsCodeInSocialRealm(ctx, userID)
			assert.Equal(t, expectedErr, err)
		})
	})
	t.Run("SendSmsCode", func(t *testing.T) {
		t.Run("not configured", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, expectedErr)
			var _, err = component.SendSmsCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("not authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCSendSmsCode.String(), realm, userID).Return(expectedErr)
			var _, err = component.SendSmsCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
		t.Run("authorized", func(t *testing.T) {
			mockAvailabilityChecker.EXPECT().CheckAvailabilityForRealm(ctx, realm, gomock.Any()).Return(ctx, nil)
			mockAuthManager.EXPECT().CheckAuthorizationOnTargetUser(ctx, KYCSendSmsCode.String(), realm, userID).Return(nil)
			mockComponent.EXPECT().SendSmsCode(ctx, realm, userID).Return("", expectedErr)
			var _, err = component.SendSmsCode(ctx, realm, userID)
			assert.Equal(t, expectedErr, err)
		})
	})
}
