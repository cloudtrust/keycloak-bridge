package statistics

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
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
