package mobilepkg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/mobile/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakClient       *mock.KeycloakClient
	configDBModule       *mock.ConfigurationDBModule
	tokenProvider        *mock.TokenProvider
	accreditationsClient *mock.AccreditationsServiceClient
	authManager          *mock.AuthorizationManager
	accountingClient     *mock.AccountingClient
	logger               log.Logger
}

func newComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient:       mock.NewKeycloakClient(mockCtrl),
		configDBModule:       mock.NewConfigurationDBModule(mockCtrl),
		tokenProvider:        mock.NewTokenProvider(mockCtrl),
		accreditationsClient: mock.NewAccreditationsServiceClient(mockCtrl),
		authManager:          mock.NewAuthorizationManager(mockCtrl),
		accountingClient:     mock.NewAccountingClient(mockCtrl),
		logger:               log.NewNopLogger(),
	}
}

func (cm *componentMocks) newComponent() Component {
	return NewComponent(cm.keycloakClient, cm.configDBModule, cm.accreditationsClient, cm.tokenProvider, cm.authManager, cm.accountingClient, cm.logger)
}

func TestToActionNames(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		assert.Nil(t, toActionNames(nil))
	})
	t.Run("Input contains two values, one need to be converted", func(t *testing.T) {
		input := []string{"IDNOW_CHECK", "unconvertable"}
		values := toActionNames(&input)
		assert.NotNil(t, values)
		assert.Len(t, *values, 2)
		assert.Contains(t, *values, actionIDNowVideoIdent)
		assert.Contains(t, *values, input[1])
	})
}

func TestChooseNotEmpty(t *testing.T) {
	empty := ""
	values := []*string{nil, &empty, nil, &empty}

	t.Run("All nil or empty", func(t *testing.T) {
		assert.Nil(t, chooseNotEmpty(values...))
	})

	one := "one"
	two := "two"
	three := "3"
	values = append(values, &one, &two, &three)
	t.Run("At least one non empty value", func(t *testing.T) {
		assert.Equal(t, &one, chooseNotEmpty(values...))
	})
}

func TestAppendIDNowActions(t *testing.T) {
	res := AppendIDNowActions(nil)
	assert.Len(t, res, 2)
	assert.Equal(t, idNowInitAuth, res[0])
	assert.Equal(t, idNowAutoIdentInitAuth, res[1])
}

func TestGetUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newComponentMocks(mockCtrl)
	component := mocks.newComponent()

	accessToken := "the-access-token"
	realm := "the-realm"
	displayName := "The Realm Name"
	userID := "the-user-id"
	anyError := errors.New("any error")
	ctx := context.WithValue(context.TODO(), cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Can't get access token", func(t *testing.T) {
		tokenError := errors.New("token error")
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", tokenError)
		_, err := component.GetUserInformation(ctx)
		assert.Equal(t, tokenError, err)
	})

	// Now, token provider will always be successful
	mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).AnyTimes()

	t.Run("Can't get realm from keycloak", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, anyError)
		_, err := component.GetUserInformation(ctx)
		assert.Equal(t, anyError, err)
	})

	// Now, keycloakClient.GetRealm() will always be successful
	mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{DisplayName: &displayName}, nil).AnyTimes()

	t.Run("Can't get user from keycloak", func(t *testing.T) {
		kcError := errors.New("keycloak error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		_, err := component.GetUserInformation(ctx)
		assert.Equal(t, kcError, err)
	})

	t.Run("Can't get user checks from database", func(t *testing.T) {
		dbError := errors.New("user DB error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(nil, dbError)
		_, err := component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	t.Run("Can't get realm admin configuration from database", func(t *testing.T) {
		dbError := errors.New("config DB error")
		mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(configuration.RealmAdminConfiguration{}, dbError)
		_, err := component.GetUserInformation(ctx)
		assert.Equal(t, dbError, err)
	})

	// No consider there is already 2 existing accreditations
	attrbs := make(kc.Attributes)
	pendings, _ := keycloakb.AddPendingCheck(nil, "check-2")
	attrbs.Set(constants.AttrbAccreditations, []string{"{}", "{}"})
	attrbs.SetString(constants.AttrbPendingChecks, *pendings)
	mocks.keycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{Attributes: &attrbs}, nil).AnyTimes()

	t.Run("Success-No problem with GLN", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		availableChecks := map[string]bool{"physical": true, "idnow": true}
		bFalse := false
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, VideoIdentificationAccountingEnabled: &bFalse, VideoIdentificationPrepaymentRequired: &bFalse}

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, len(availableChecks))
	})

	t.Run("Success-Missing GLN", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		bFalse := false
		availableChecks := map[string]bool{"physical": true, "IDNow": true}
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, VideoIdentificationAccountingEnabled: &bFalse, VideoIdentificationPrepaymentRequired: &bFalse}
		bTrue := true
		adminConf.ShowGlnEditing = &bTrue
		expectedActionsCount := len(availableChecks) - 1

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-User has no rights for IDNow", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		bFalse := false
		availableChecks := map[string]bool{"physical": true, "IDNow": true}
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse, VideoIdentificationAccountingEnabled: &bFalse, VideoIdentificationPrepaymentRequired: &bFalse}
		expectedActionsCount := len(availableChecks) - 1

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(errors.New("any error"))
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(errors.New("any error"))

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-User has rights for IDNow", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		bFalse := false
		availableChecks := map[string]bool{"physical": true, "IDNow": true}
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse, VideoIdentificationAccountingEnabled: &bFalse, VideoIdentificationPrepaymentRequired: &bFalse}
		expectedActionsCount := len(availableChecks)

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, expectedActionsCount)
	})

	t.Run("Success-action is pending", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		bFalse := false
		availableChecks := map[string]bool{"check-2": true, "check-3": true}
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, ShowGlnEditing: &bFalse, VideoIdentificationAccountingEnabled: &bFalse, VideoIdentificationPrepaymentRequired: &bFalse}

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		pendingAction := "check-2"
		pending := "PENDING"
		now := time.Now().UTC()
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{{Nature: &pendingAction, Status: &pending, DateTime: &now}}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Checks, len(checks))
		assert.Len(t, *userInfo.Actions, 1)
		assert.Len(t, *userInfo.PendingActions, 1)
		assert.Equal(t, "check-3", (*userInfo.Actions)[0])
		assert.Equal(t, "check-2", (*userInfo.PendingActions)[0])
	})

	t.Run("Success-Voucher enabled for video", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		availableChecks := map[string]bool{"physical": true, "IDNow": true}
		bTrue := true
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, VideoIdentificationAccountingEnabled: &bTrue, VideoIdentificationPrepaymentRequired: &bTrue}

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)
		mocks.accountingClient.EXPECT().GetBalance(ctx, realm, userID, "VIDEO_IDENTIFICATION").Return(float64(10), nil).Times(1)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, 2)
		assert.Len(t, *userInfo.Actions, 2)
	})

	t.Run("Success-Voucher enabled for video, not enough balance", func(t *testing.T) {
		checks := []accreditationsclient.CheckRepresentation{{}, {}}
		availableChecks := map[string]bool{"physical": true, "IDNow": true}
		bTrue := true
		adminConf := configuration.RealmAdminConfiguration{AvailableChecks: availableChecks, VideoIdentificationAccountingEnabled: &bTrue, VideoIdentificationPrepaymentRequired: &bTrue}

		mocks.accreditationsClient.EXPECT().GetChecks(ctx, realm, userID).Return(checks, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realm, userID).Return([]accreditationsclient.CheckRepresentation{}, nil)
		mocks.configDBModule.EXPECT().GetAdminConfiguration(ctx, realm).Return(adminConf, nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowInitAuth, realm, userID).Return(nil)
		mocks.authManager.EXPECT().CheckAuthorizationOnTargetUser(gomock.Any(), idNowAutoIdentInitAuth, realm, userID).Return(nil)
		mocks.accountingClient.EXPECT().GetBalance(ctx, realm, userID, "VIDEO_IDENTIFICATION").Return(float64(0), nil).Times(1)

		userInfo, err := component.GetUserInformation(ctx)
		assert.Nil(t, err)
		assert.Len(t, *userInfo.Accreditations, 2)
		assert.Len(t, *userInfo.Checks, 2)
		assert.Len(t, *userInfo.Actions, 1)
	})
}
