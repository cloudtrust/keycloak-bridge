package events

//go:generate mockgen -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/pkg/events EventsDBModule

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockEventsDBModule = mock.NewEventsDBModule(mockCtrl)

	params := make(map[string]string)

	component := NewEventsComponent(mockEventsDBModule)

	// Test GetEvents
	{
		// Prepare test
		mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), params).Return([]api.AuditRepresentation{}, nil).Times(1)

		// Execute test
		res, err := component.GetEvents(context.Background(), params)

		// Check result
		assert.Nil(t, err)
		assert.Equal(t, 0, len(res))
	}

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

	// Test GetUserEvents
	{
		testGetUserEvents(t, mockEventsDBModule, initMap("realm", "master", "userID", "123-456"), []api.AuditRepresentation{}, nil)
		testGetUserEvents(t, mockEventsDBModule, initMap("realm", "master", "userID", ""), nil, keycloakb.CreateMissingParameterError(""))
		testGetUserEvents(t, mockEventsDBModule, initMap("realm", "master"), nil, keycloakb.CreateMissingParameterError(""))
		testGetUserEvents(t, mockEventsDBModule, initMap("realm", "", "userID", "123-456"), nil, keycloakb.CreateMissingParameterError(""))
		testGetUserEvents(t, mockEventsDBModule, initMap("userID", "123-456"), nil, keycloakb.CreateMissingParameterError(""))
	}
}

func testGetUserEvents(t *testing.T, mockEventsDBModule *mock.EventsDBModule, params map[string]string, expectedResult []api.AuditRepresentation, expectedError error) {
	// Prepare test
	var times int
	if expectedError == nil {
		times = 1
	}
	mockEventsDBModule.EXPECT().GetEvents(gomock.Any(), params).Return(expectedResult, expectedError).Times(times)
	component := NewEventsComponent(mockEventsDBModule)

	// Execute test
	res, err := component.GetUserEvents(context.Background(), params)

	// Check result
	if expectedError == nil {
		assert.Nil(t, err)
		assert.Equal(t, expectedResult, res)
	} else {
		assert.NotNil(t, err)
		assert.Equal(t, 0, len(res))
	}
}

func initMap(params ...string) map[string]string {
	res := make(map[string]string)

	noTuples := len(params)
	for i := 0; i+1 < noTuples; i = i + 2 {
		res[params[i]] = params[i+1]
	}

	return res
}
