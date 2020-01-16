package statistics

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func executeTest(t *testing.T, tester func(mockDBModule *mock.EventsDBModule, component Component)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDBModule = mock.NewEventsDBModule(mockCtrl)
	var mockKcClient = mock.NewKcClient(mockCtrl)
	var mockLogger = log.NewNopLogger()
	tester(mockDBModule, NewComponent(mockDBModule, mockKcClient, mockLogger))
}

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

	{
		// db.GetLastConnection fails
		mockDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(int64(0), errDbModule).Times(1)
		_, err := component.GetStatistics(context.TODO(), realm)
		assert.Equal(t, errDbModule, err)
	}

	{
		// success
		mockDBModule.EXPECT().GetLastConnection(gomock.Any(), realm).Return(expected.LastConnection, nil).Times(1)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "12 HOUR").Return(expected.TotalConnections.LastTwelveHours, nil).Times(1)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 DAY").Return(expected.TotalConnections.LastDay, nil).Times(1)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 WEEK").Return(expected.TotalConnections.LastWeek, nil).Times(1)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 MONTH").Return(expected.TotalConnections.LastMonth, nil).Times(1)
		mockDBModule.EXPECT().GetTotalConnectionsCount(gomock.Any(), realm, "1 YEAR").Return(expected.TotalConnections.LastYear, nil).Times(1)
		res, err := component.GetStatistics(context.TODO(), realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	}
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

	{ // fails
		mockKcClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, errors.New("error")).Times(1)
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.NotNil(t, err)
		assert.Equal(t, api.StatisticsUsersRepresentation{}, res)
	}

	{ // success

		mockKcClient.EXPECT().GetStatisticsUsers(accessToken, realm).Return(statisticsKC, nil).Times(1)
		res, err := component.GetStatisticsUsers(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, expected, res)
	}
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

	{ // fails
		mockKcClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, errors.New("error")).Times(1)
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}

	{ // success

		mockKcClient.EXPECT().GetStatisticsAuthenticators(accessToken, realm).Return(statisticsKC, nil).Times(1)
		res, err := component.GetStatisticsAuthenticators(ctx, realm)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	}
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

	{ // fails - statistics by hours
		mockDBModule.EXPECT().GetTotalConnectionsHoursCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error")).Times(1)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "hours", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
	{ // fails - statistics by days
		mockDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error")).Times(1)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
	{ // fails - statistics by months
		mockDBModule.EXPECT().GetTotalConnectionsMonthsCount(ctx, realm, gomock.Any(), timeshift).Return([][]int64{}, errors.New("error")).Times(1)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "months", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
	{ // fails - invalid param
		res, err := component.GetStatisticsAuthentications(ctx, realm, "ramdom", nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}

	{ // success
		mockDBModule.EXPECT().GetTotalConnectionsDaysCount(ctx, realm, gomock.Any(), timeshift).Return(statisticsKC, nil).Times(1)
		res, err := component.GetStatisticsAuthentications(ctx, realm, "days", nil)
		assert.Nil(t, err)
		assert.Equal(t, statisticsKC, res)
	}
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
		{"123", "LOGON_OK", "user", "127.0.0.1"},
	}

	{ // fails
		mockDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return([]api.StatisticsConnectionRepresentation{}, errors.New("error")).Times(1)
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "9")
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}

	{ // success
		mockDBModule.EXPECT().GetLastConnections(ctx, realm, "9").Return(resExpected, nil).Times(1)
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "9")

		assert.Nil(t, err)
		assert.Equal(t, resExpected, res)
	}
	{ // fails - invalid param max
		res, err := component.GetStatisticsAuthenticationsLog(ctx, realm, "101")

		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
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
