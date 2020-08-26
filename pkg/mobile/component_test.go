package mobilepkg

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockTokenProvider := mock.NewTokenProvider(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	var component = NewComponent(mockKeycloakClient, mockConfigurationDBModule, mockUsersDetailsDBModule, mockTokenProvider, mockLogger)

	var accessToken = "the-access-token"
	var realm = "the-realm"
	var userID = "the-user-id"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Can't get access token", func(t *testing.T) {
		var tokenError = errors.New("token error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, tokenError, err)
	})

	t.Run("Can't get user from keycloak", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, kcError, err)
	})

	t.Run("Can't get user checks from database", func(t *testing.T) {
		var dbError = errors.New("user DB error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDetailsDBModule.EXPECT().GetChecks(ctx, realm, userID, false).Return(nil, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get realm admin configuration from database", func(t *testing.T) {
		var dbError = errors.New("config DB error")
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDetailsDBModule.EXPECT().GetChecks(ctx, realm, userID, false).Return([]dto.DBCheck{}, nil)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Success", func(t *testing.T) {
		var attrbs = make(kc.Attributes)
		attrbs.Set(constants.AttrbAccreditations, []string{"{}", "{}"})

		var checks = []dto.DBCheck{dto.DBCheck{}, dto.DBCheck{}}

		var availableChecks = map[string]bool{"one": true, "two": true}

		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{Attributes: &attrbs}, nil)
		mockUsersDetailsDBModule.EXPECT().GetChecks(ctx, realm, userID, false).Return(checks, nil)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{AvailableChecks: availableChecks}, nil)
		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, len(availableChecks))
	})
}
