package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type keycloakTechnicalClientMocks struct {
	tokenProvider *mock.OidcTokenProvider
	kcClient      *mock.KeycloakForTechnicalClient
	logger        *mock.Logger
}

func createKcTechnicalClientMocks(ctrl *gomock.Controller) *keycloakTechnicalClientMocks {
	return &keycloakTechnicalClientMocks{
		tokenProvider: mock.NewOidcTokenProvider(ctrl),
		kcClient:      mock.NewKeycloakForTechnicalClient(ctrl),
		logger:        mock.NewLogger(ctrl),
	}
}

func createKcTechnicalClient(mocks *keycloakTechnicalClientMocks) *kcTechnicalClient {
	return NewKeycloakTechnicalClient(mocks.tokenProvider, "tkrealm", mocks.kcClient, mocks.logger).(*kcTechnicalClient)
}

func TestGetRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createKcTechnicalClientMocks(mockCtrl)
	var kcTechClient = createKcTechnicalClient(mocks)

	var accessToken = "access-token"
	var anyError = errors.New("any error")
	var ctx = context.TODO()

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Token provider fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		var _, err = kcTechClient.GetRealm(ctx, realm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.kcClient.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, nil)

		var _, err = kcTechClient.GetRealm(ctx, realm)
		assert.Nil(t, err)
	})
}

func TestGetUsers(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createKcTechnicalClientMocks(mockCtrl)
	var kcTechClient = createKcTechnicalClient(mocks)

	var targetRealm = "target"
	var accessToken = "access-token"
	var anyError = errors.New("any error")
	var ctx = context.TODO()

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Token provider fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		var _, err = kcTechClient.GetUsers(ctx, targetRealm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.kcClient.EXPECT().GetUsers(accessToken, kcTechClient.tokenRealm, targetRealm).Return(kc.UsersPageRepresentation{}, nil)

		var _, err = kcTechClient.GetUsers(ctx, targetRealm)
		assert.Nil(t, err)
	})
}

func TestLogoutAllSessions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createKcTechnicalClientMocks(mockCtrl)
	var kcTechClient = createKcTechnicalClient(mocks)

	var accessToken = "access-token"
	var anyError = errors.New("any error")
	var userID = "user-id"
	var ctx = context.TODO()

	mocks.logger.EXPECT().Error(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Token provider fails", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)

		var err = kcTechClient.LogoutAllSessions(ctx, realm, userID)
		assert.Equal(t, anyError, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.kcClient.EXPECT().LogoutAllSessions(accessToken, realm, userID).Return(nil)

		var err = kcTechClient.LogoutAllSessions(ctx, realm, userID)
		assert.Nil(t, err)
	})
}
