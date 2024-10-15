package statistics

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/idnowclient"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakClient *mock.KcClient
	accredsService *mock.AccreditationsServiceClient
	idnowService   *mock.IdnowServiceClient
}

func newComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient: mock.NewKcClient(mockCtrl),
		accredsService: mock.NewAccreditationsServiceClient(mockCtrl),
		idnowService:   mock.NewIdnowServiceClient(mockCtrl),
	}
}

func (cm *componentMocks) newComponent() *component {
	return NewComponent(cm.keycloakClient, cm.accredsService, cm.idnowService, log.NewNopLogger()).(*component)
}

func TestGetStatisticsIdentifications(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newComponentMocks(mockCtrl)
	component := mocks.newComponent()

	testError := errors.New("test error")
	realm := "the_realm_name"
	expected := api.IdentificationStatisticsRepresentation{}
	ctx := context.Background()

	t.Run("accreditation service error", func(t *testing.T) {
		mocks.accredsService.EXPECT().GetIdentityChecksByNature(ctx, realm).Return([]accreditationsclient.NatureCheckCount{}, testError)

		_, err := component.GetStatisticsIdentifications(ctx, realm)
		assert.NotNil(t, err)
	})

	t.Run("idnow service error", func(t *testing.T) {
		mocks.accredsService.EXPECT().GetIdentityChecksByNature(ctx, realm).Return([]accreditationsclient.NatureCheckCount{}, nil)
		mocks.idnowService.EXPECT().GetIdentificationsByType(ctx, realm).Return(idnowclient.IdentificationStatistics{}, testError)

		_, err := component.GetStatisticsIdentifications(ctx, realm)
		assert.NotNil(t, err)
	})

	t.Run("success", func(t *testing.T) {
		expected.VideoIdentifications = 100
		expected.AutoIdentifications = 33
		expected.BasicIdentifications = 52
		expected.PhysicalIdentifications = 21

		mocks.accredsService.EXPECT().GetIdentityChecksByNature(ctx, realm).Return([]accreditationsclient.NatureCheckCount{
			{Nature: ptr("PHYSICAL_CHECK"), Count: &expected.PhysicalIdentifications},
			{Nature: ptr("BASIC_CHECK"), Count: &expected.BasicIdentifications},
			{Nature: ptr("IDNOW_CHECK"), Count: intPtr(48)},
			{Nature: ptr("AUTO_IDENT_IDNOW_CHECK"), Count: intPtr(19)},
		}, nil)

		mocks.idnowService.EXPECT().GetIdentificationsByType(ctx, realm).Return(idnowclient.IdentificationStatistics{
			VideoIdentifications: expected.VideoIdentifications,
			AutoIdentifications:  expected.AutoIdentifications,
		}, nil)

		res, err := component.GetStatisticsIdentifications(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsUsers(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newComponentMocks(mockCtrl)
	component := mocks.newComponent()

	realm := "the_realm_name"
	accessToken := "TOKEN=="
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	statisticsKC := kc.StatisticsUsersRepresentation{
		Total:    3,
		Disabled: 0,
		Inactive: 2,
	}
	expected := api.StatisticsUsersRepresentation{
		Total:    3,
		Disabled: 0,
		Inactive: 2,
	}

	t.Run("fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, errors.New("error"))
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.NotNil(t, err)
		assert.Equal(t, api.StatisticsUsersRepresentation{}, res)
	})

	t.Run("success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, nil)
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsAuthenticators(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newComponentMocks(mockCtrl)
	component := mocks.newComponent()

	realm := "the_realm_name"
	accessToken := "TOKEN=="
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	statisticsKC := map[string]int64{
		"password": 3,
		"otp":      1,
	}

	t.Run("fails", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, errors.New("error"))
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, nil)
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	})
}

func TestGetActions(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := newComponentMocks(mockCtrl)
	component := mocks.newComponent()

	realm := "the_realm_name"
	accessToken := "TOKEN=="
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	res, err := component.GetActions(ctx)

	assert.Nil(t, err)
	assert.Equal(t, len(security.Actions.GetActionsForAPIs(security.BridgeService, security.StatisticAPI)), len(res))
}
