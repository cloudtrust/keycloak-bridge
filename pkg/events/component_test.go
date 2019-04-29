package events

//go:generate mockgen -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/pkg/events EventsDBModule

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func executeTest(t *testing.T, tester func(mockEventsDBModule *mock.EventsDBModule, component EventsComponent)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockEventsDBModule = mock.NewEventsDBModule(mockCtrl)
	tester(mockEventsDBModule, NewEventsComponent(mockEventsDBModule))
}

func TestGetEvents(t *testing.T) {
	executeTest(t, func(mockEventsDBModule *mock.EventsDBModule, component EventsComponent) {
		params := make(map[string]string)
		var emptyAudits [0]api.AuditRepresentation
		var expected api.AuditEventsRepresentation
		expected.Count = 1
		expected.Events = emptyAudits[:]
		// Prepare test
		mockEventsDBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(expected.Count, nil).Times(1)
		mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expected.Events, nil).Times(1)

		// Execute test
		res, err := component.GetEvents(context.Background(), params)

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, expected.Count, res.Count)
		assert.Equal(t, 0, len(res.Events))
	})
}

func TestGetUserEventsWithResult(t *testing.T) {
	executeTest(t, func(mockEventsDBModule *mock.EventsDBModule, component EventsComponent) {
		params := initMap("realm", "master", "userID", "123-456")
		expectedCount := 1
		expectedResult := []api.AuditRepresentation{}
		mockEventsDBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(expectedCount, nil).Times(1)
		mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expectedResult, nil).Times(1)

		// Execute test
		res, err := component.GetUserEvents(context.Background(), params)

		assert.Nil(t, err)
		assert.Equal(t, expectedCount, res.Count)
		assert.Equal(t, expectedResult, res.Events)
	})
}

func TestGetUserEventsWithZeroCount(t *testing.T) {
	executeTest(t, func(mockEventsDBModule *mock.EventsDBModule, component EventsComponent) {
		// Prepare test
		params := initMap("realm", "master", "userID", "123-456")
		mockEventsDBModule.EXPECT().GetEventsCount(gomock.Any(), params).Return(0, nil).Times(1)
		mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), gomock.Any()).Times(0)

		// Execute test
		res, err := component.GetUserEvents(context.Background(), params)

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, 0, res.Count)
	})
}

func testInvalidRealmUserID(t *testing.T, params map[string]string) {
	executeTest(t, func(mockEventsDBModule *mock.EventsDBModule, component EventsComponent) {
		// Prepare test
		mockEventsDBModule.EXPECT().GetEventsCount(gomock.Any(), gomock.Any()).Times(0)
		mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), gomock.Any()).Times(0)

		// Execute test
		res, err := component.GetUserEvents(context.Background(), params)

		// Check result
		assert.NotNil(t, err)
		assert.Equal(t, 0, res.Count)
	})
}

func TestGetUserEventsEmptyUserID(t *testing.T) {
	testInvalidRealmUserID(t, initMap("realm", "master", "userID", ""))
}

func TestGetUserEventsMissingUserID(t *testing.T) {
	testInvalidRealmUserID(t, initMap("realm", "master"))
}

func TestGetUserEventsEmptyRealm(t *testing.T) {
	testInvalidRealmUserID(t, initMap("realm", "", "userID", "123-456-789"))
}

func TestGetUserEventsMissingRealm(t *testing.T) {
	testInvalidRealmUserID(t, initMap("userID", "123-456-789"))
}

func initMap(params ...string) map[string]string {
	res := make(map[string]string)

	noTuples := len(params)
	for i := 0; i+1 < noTuples; i = i + 2 {
		res[params[i]] = params[i+1]
	}

	return res
}

func TestGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockEventsDBModule = mock.NewEventsDBModule(mockCtrl)
	component := NewEventsComponent(mockEventsDBModule)

	// Test GetEventsSummary
	{
		// Prepare test
		mockEventsDBModule.EXPECT().GetEventsSummary(gomock.Any()).Return(api.EventSummaryRepresentation{
			Origins: []string{
				"origin-1",
			},
		}, nil).Times(1)

		// Execute test
		res, err := component.GetEventsSummary(context.Background())

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Origins))
	}
}
