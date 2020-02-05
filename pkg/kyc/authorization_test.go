package kyc

import (
	"context"
	"errors"
	"testing"

	logger "github.com/cloudtrust/common-service/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	"github.com/cloudtrust/keycloak-bridge/pkg/kyc/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeAuthorizationRegisterComponentMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)
	var mockAuthManager = mock.NewAuthorizationManager(mockCtrl)

	var ctx = context.TODO()
	var realm = "master"
	var user = apikyc.UserRepresentation{}
	var username = "user4673"
	var group = RegistrationOfficer
	var expectedErr = errors.New("")

	var component = MakeAuthorizationRegisterComponentMW(realm, logger.NewNopLogger(), mockAuthManager)(mockComponent)

	t.Run("GetActions - not authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetActions.String(), gomock.Any()).Return(expectedErr)
		var _, err = component.GetActions(ctx)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("GetActions - authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetRealm(ctx, KYCGetActions.String(), gomock.Any()).Return(nil)
		mockComponent.EXPECT().GetActions(ctx).Return([]apikyc.ActionRepresentation{}, expectedErr).Times(1)
		var _, err = component.GetActions(ctx)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("GetUser - not authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetGroup(ctx, KYCGetUser.String(), realm, group).Return(expectedErr)
		var _, err = component.GetUser(ctx, username)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("GetUser - authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetGroup(ctx, KYCGetUser.String(), realm, group).Return(nil)
		mockComponent.EXPECT().GetUser(ctx, username).Return(apikyc.UserRepresentation{}, expectedErr).Times(1)
		var _, err = component.GetUser(ctx, username)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("ValidateUser - not authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetGroup(ctx, KYCValidateUser.String(), realm, group).Return(expectedErr)
		var err = component.ValidateUser(ctx, username, user)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("ValidateUser - authorized", func(t *testing.T) {
		mockAuthManager.EXPECT().CheckAuthorizationOnTargetGroup(ctx, KYCValidateUser.String(), realm, group).Return(nil)
		mockComponent.EXPECT().ValidateUser(ctx, username, user).Return(expectedErr).Times(1)
		var err = component.ValidateUser(ctx, username, user)
		assert.Equal(t, expectedErr, err)
	})
}
