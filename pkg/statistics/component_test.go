package statistics

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetStatistics(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

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
		mockDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(int64(0), errDbModule)
		_, err := component.GetStatistics(context.TODO(), realm)
		assert.Equal(t, errDbModule, err)
	})

	t.Run("success", func(t *testing.T) {
		mockDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(expected.LastConnection, nil)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "12 HOUR").Return(expected.TotalConnections.LastTwelveHours, nil)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 DAY").Return(expected.TotalConnections.LastDay, nil)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 WEEK").Return(expected.TotalConnections.LastWeek, nil)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 MONTH").Return(expected.TotalConnections.LastMonth, nil)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 YEAR").Return(expected.TotalConnections.LastYear, nil)
		res, err := component.GetStatistics(context.TODO(), realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsIdentifications(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

	var errDbModule = errors.New("Dummy error in db module")
	var realm = "the_realm_name"
	var expected = api.IdentificationStatisticsRepresentation{}
	var videoIdentSearch = map[string]string{"realm": realm, "ctEventType": "VALIDATION_STORE_CHECK_SUCCESS"}

	t.Run("db.GetLastConnection fails", func(t *testing.T) {
		mockDBModule.EXPECT().GetEventsCount(gomock.Any(), videoIdentSearch).Return(0, errDbModule)
		_, err := component.GetStatisticsIdentifications(context.TODO(), realm)
		assert.Equal(t, errDbModule, err)
	})

	t.Run("success", func(t *testing.T) {
		expected.VideoIdentifications = 100
		mockDBModule.EXPECT().GetEventsCount(gomock.Any(), videoIdentSearch).Return(expected.VideoIdentifications, nil)
		res, err := component.GetStatisticsIdentifications(context.TODO(), realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsUsers(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

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
		mockKcClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, errors.New("error"))
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.NotNil(t, err)
		assert.Equal(t, api.StatisticsUsersRepresentation{}, res)
	})

	t.Run("success", func(t *testing.T) {
		mockKcClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, nil)
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	})
}

func TestGetStatisticsAuthenticators(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	statisticsKC := map[string]int64{
		"password": 3,
		"otp":      1,
	}

	t.Run("fails", func(t *testing.T) {
		mockKcClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, errors.New("error"))
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("success", func(t *testing.T) {
		mockKcClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, nil)
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	})
}

func TestGetStatisticsAuthentications(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

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
		mockDBModule.EXPECT().GetTotalConnectionsHoursCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
		res, err := component.GetStatisticsAuthentications(ctx, realm, "hours", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("fails - statistics by days", func(t *testing.T) {
		mockDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("fails - statistics by months", func(t *testing.T) {
		mockDBModule.EXPECT().GetTotalConnectionsMonthsCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error"))
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
		mockDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return(statisticsKC, nil)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	})
}

func TestGetStatisticsAuthenticationsLog(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	var resExpected = []api.StatisticsConnectionRepresentation{
		{Date: "01.02.2003", Result: "LOGON_OK", User: "user", IP: "127.0.0.1"},
	}

	t.Run("fails", func(t *testing.T) {
		mockDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return([]api.StatisticsConnectionRepresentation{}, errors.New("error"))
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "9")
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
	t.Run("success", func(t *testing.T) {
		mockDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return(resExpected, nil)
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

	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockDBModule, mockKcClient, mockLogger)

	var realm = "the_realm_name"
	var accessToken = "TOKEN=="
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	res, err := component.GetActions(ctx)

	assert.Nil(t, err)
	assert.Equal(t, len(actions), len(res))
}
