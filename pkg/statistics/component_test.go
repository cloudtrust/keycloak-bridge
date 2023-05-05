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
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

type componentMocks struct {
	eventsDBModule *mock.EventsDBModule
	keycloakClient *mock.KcClient
	accredsService *mock.AccreditationsServiceClient
}

func newComponentMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		eventsDBModule: mock.NewEventsDBModule(mockCtrl),
		keycloakClient: mock.NewKcClient(mockCtrl),
		accredsService: mock.NewAccreditationsServiceClient(mockCtrl),
	}
}

func (cm *componentMocks) newComponent() *component {
	return NewComponent(cm.eventsDBModule, cm.keycloakClient, cm.accredsService, log.NewNopLogger()).(*component)
}

func TestGetStatistics(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var errDbModule = errors.New("Dummy error in db module")
	var realm = "the_realm_name"
	var expected = api.StatisticsRepresentation{
		LastConnection: 1234567890,
		TotalConnections: api.StatisticsConnectionsRepresentation{
			LastTwelveHours: 12,
			LastDay:         1,
			LastWeek:        7,
			LastMonth:       30,
			LastYear:        365,
		},
	}

	t.Run("db.GetLastConnection fails", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(int64(0), errDbModule)
		_, err := component.GetStatistics(context.TODO(), realm)
		assert.Equal(t, errDbModule, err)
	})

	t.Run("success", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(expected.LastConnection, nil)
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "12 HOUR").Return(expected.TotalConnections.LastTwelveHours, nil)
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 DAY").Return(expected.TotalConnections.LastDay, nil)
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 WEEK").Return(expected.TotalConnections.LastWeek, nil)
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 MONTH").Return(expected.TotalConnections.LastMonth, nil)
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 YEAR").Return(expected.TotalConnections.LastYear, nil)
		res, err := component.GetStatistics(context.TODO(), realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsIdentifications(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var errDbModule = errors.New("Dummy error in db module")
	var realm = "the_realm_name"
	var expected = api.IdentificationStatisticsRepresentation{}
	var ctx = context.Background()

	t.Run("success", func(t *testing.T) {
		mocks.accredsService.EXPECT().GetIdentityChecksByNature(ctx, realm).Return([]accreditationsclient.NatureCheckCount{}, errDbModule)

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
			{Nature: ptr("IDNOW_CHECK"), Count: &expected.VideoIdentifications},
			{Nature: ptr("AUTO_IDENT_IDNOW_CHECK"), Count: &expected.AutoIdentifications},
		}, nil)

		res, err := component.GetStatisticsIdentifications(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsUsers(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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

func TestGetStatisticsAuthentications(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var timeshift = 0
	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	statisticsKC := make([][]int64, 2)
	statisticsKC[0] = make([]int64, 2)
	statisticsKC[1] = make([]int64, 2)
	statisticsKC[0][0] = 12
	statisticsKC[0][1] = 11
	statisticsKC[1][0] = 11
	statisticsKC[1][1] = 11

	t.Run("fails - statistics by hours", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsHoursCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
		res, err := component.GetStatisticsAuthentications(ctx, realm, "hours", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("fails - statistics by days", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("fails - statistics by months", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsMonthsCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
		res, err := component.GetStatisticsAuthentications(ctx, realm, "months", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("fails - invalid param", func(t *testing.T) {
		res, err := component.GetStatisticsAuthentications(ctx, realm, "ramdom", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("success", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return(statisticsKC, nil)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	})
}

func TestGetStatisticsAuthenticationsLog(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	var resExpected = []api.StatisticsConnectionRepresentation{
		{Date: "01.02.2003", Result: "LOGON_OK", User: "user", IP: "127.0.0.1"},
	}

	t.Run("fails", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return([]api.StatisticsConnectionRepresentation{}, errors.New("error"))
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "9")
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("success", func(t *testing.T) {
		mocks.eventsDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return(resExpected, nil)
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "9")

		assert.Nil(t, err)
		assert.Equal(t, resExpected, res)
	})
	t.Run("fails - invalid param max", func(t *testing.T) {
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "101")

		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetActions(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = newComponentMocks(mockCtrl)
	var component = mocks.newComponent()

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	res, err := component.GetActions(ctx)

	assert.Nil(t, err)
	assert.Equal(t, len(security.Actions.GetActionsForAPIs(security.BridgeService, security.StatisticAPI)), len(res))
}
