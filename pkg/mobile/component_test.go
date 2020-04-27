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
	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDBModule := mock.NewUsersDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	var component = NewComponent(mockKeycloakAccountClient, mockConfigurationDBModule, mockUsersDBModule, mockLogger)

	var accessToken = "the-access-token"
	var realm = "the-realm"
	var userID = "the-user-id"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Can't get user from keycloak", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realm).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, kcError, err)
	})

	t.Run("Can't get user checks from database", func(t *testing.T) {
		var dbError = errors.New("user DB error")
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realm).Return(kc.UserRepresentation{}, nil)
		mockUsersDBModule.EXPECT().GetUserChecks(ctx, realm, userID).Return(nil, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get realm admin configuration from database", func(t *testing.T) {
		var dbError = errors.New("config DB error")
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realm).Return(kc.UserRepresentation{}, nil)
		mockUsersDBModule.EXPECT().GetUserChecks(ctx, realm, userID).Return([]dto.DBCheck{}, nil)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Success", func(t *testing.T) {
		var attrbs = make(kc.Attributes)
		attrbs.Set(constants.AttrbAccreditations, []string{"{}", "{}"})

		var checks = []dto.DBCheck{dto.DBCheck{}, dto.DBCheck{}}

		var availableChecks = map[string]bool{"one": true, "two": true}

		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realm).Return(kc.UserRepresentation{Attributes: &attrbs}, nil)
		mockUsersDBModule.EXPECT().GetUserChecks(ctx, realm, userID).Return(checks, nil)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{AvailableChecks: availableChecks}, nil)
		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, len(availableChecks))
	})
}
