package mobilepkg

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type componentMocks struct {
	keycloakClient *mock.KeycloakClient
	configDBModule *mock.ConfigurationDBModule
	tokenProvider  *mock.TokenProvider
	usersDetailsDB *mock.UsersDetailsDBModule
	authManager    *mock.AuthorizationManager
	logger         log.Logger
}

func newComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient: mock.NewKeycloakClient(mockCtrl),
		configDBModule: mock.NewConfigurationDBModule(mockCtrl),
		tokenProvider:  mock.NewTokenProvider(mockCtrl),
		usersDetailsDB: mock.NewUsersDetailsDBModule(mockCtrl),
		authManager:    mock.NewAuthorizationManager(mockCtrl),
		logger:         log.NewNopLogger(),
	}
}

func (cm *componentMocks) newComponent() Component {
	return NewComponent(cm.keycloakClient, cm.configDBModule, cm.usersDetailsDB, cm.tokenProvider, cm.authManager, cm.logger)
}

func TestAppendIDNowActions(t *testing.T) {
	var res = AppendIDNowActions(nil)
	assert.Len(t, res, 1)
	assert.Equal(t, idNowInitActionName, res[0])
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var accessToken = "the-access-token"
	var realm = "the-realm"
	var userID = "the-user-id"
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Can't get access token", func(t *testing.T) {
		var tokenError = errors.New("token error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, tokenError, err)
	})

	// Now, token provider will always be successful
	mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).AnyTimes()

	t.Run("Can't get user from keycloak", func(t *testing.T) {
		var kcError = errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, kcError, err)
	})

	t.Run("Can't get user checks from database", func(t *testing.T) {
		var dbError = errors.New("user DB error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(nil, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get realm admin configuration from database", func(t *testing.T) {
		var dbError = errors.New("config DB error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return([]dto.DBCheck{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, dbError)
		var _, err = component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	// No consider there is already 2 existing accreditations
	var attrbs = make(kc.Attributes)
	var pendings, _ = keycloakb.AddPendingCheck(nil, "check-2")
	attrbs.Set(constants.AttrbAccreditations, []string{"{}", "{}"})
	attrbs.SetString(constants.AttrbPendingChecks, *pendings)
	mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{Attributes: &attrbs}, nil).AnyTimes()

	t.Run("Success-No problem with GLN", func(t *testing.T) {
		var checks = []dto.DBCheck{{}, {}}
		var availableChecks = map[string]bool{"physical": true, "idnow": true}
		var adminConf = configuration.RealmAdminConfiguration{AvailableChecks: availableChecks}

		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitActionName, realm, userID).Return(nil)

		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, len(availableChecks))
	})

	t.Run("Success-Missing GLN", func(t *testing.T) {
		var checks = []dto.DBCheck{{}, {}}
		var availableChecks = map[string]bool{"physical": true, "IDNow": true}
		var adminConf = configuration.RealmAdminConfiguration{AvailableChecks: availableChecks}
		var bTrue = true
		adminConf.ShowGlnEditing = &bTrue
		var expectedActionsCount = len(availableChecks) - 1

		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitActionName, realm, userID).Return(nil)

		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-User has no rights for IDNow", func(t *testing.T) {
		var checks = []dto.DBCheck{{}, {}}
		var bFalse = false
		var availableChecks = map[string]bool{"physical": true, "IDNow": true}
		var adminConf = configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse}
		var expectedActionsCount = len(availableChecks) - 1

		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitActionName, realm, userID).Return(errors.New("any error"))

		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-User has rights for IDNow", func(t *testing.T) {
		var checks = []dto.DBCheck{{}, {}}
		var bFalse = false
		var availableChecks = map[string]bool{"physical": true, "IDNow": true}
		var adminConf = configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse}
		var expectedActionsCount = len(availableChecks)

		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitActionName, realm, userID).Return(nil)

		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-action is pending", func(t *testing.T) {
		var checks = []dto.DBCheck{{}, {}}
		var bFalse = false
		var availableChecks = map[string]bool{"check-2": true, "check-3": true}
		var adminConf = configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse}

		mocks.usersDetailsDB.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitActionName, realm, userID).Return(nil)

		var userInfo, err = component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, 1)
		assert.Len(t, *userInfo.PendingActions, 1)
		assert.Equal(t, "check-3", (*userInfo.Actions)[0])
		assert.Equal(t, "check-2", (*userInfo.PendingActions)[0])
	})
}
