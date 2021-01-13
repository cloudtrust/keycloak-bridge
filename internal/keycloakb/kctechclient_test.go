package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

type keycloakTechnicalClientMocks struct {
	tokenProvider *mock.OidcTokenProvider
	kcClient      *mock.KeycloakClient
	logger        *mock.Logger
}

func createKcTechnicalClientMocks(ctrl *gomock.Controller) *keycloakTechnicalClientMocks {
	return &keycloakTechnicalClientMocks{
		tokenProvider: mock.NewOidcTokenProvider(ctrl),
		kcClient:      mock.NewKeycloakClient(ctrl),
		logger:        mock.NewLogger(ctrl),
	}
}

func createKcTechnicalClient(mocks *keycloakTechnicalClientMocks) *kcTechnicalClient {
	return NewKeycloakTechnicalClient(mocks.tokenProvider, mocks.kcClient, mocks.logger).(*kcTechnicalClient)
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
