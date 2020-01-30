package keycloakb

import (
	"context"
	"database/sql"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestModuleGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	{
		// Multiple values not yet supported for exclude
		params := map[string]string{"exclude": "value1,value2"}
		_, err := module.GetEvents(context.Background(), params)

		assert.NotNil(t, err)
	}

	{
		params := map[string]string{"origin": "origin-1", "max": "5"}
		var empty [0]api.AuditRepresentation
		var expectedResult = empty[:]
		var expectedError error = errorhandler.CreateMissingParameterError("")
		var rows sql.Rows
		dbEvents.EXPECT().Query(gomock.Any(), params["origin"], params["origin"], nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, params["max"]).Return(&rows, expectedError).Times(1)
		res, err := module.GetEvents(context.Background(), params)

		assert.Equal(t, expectedResult, res)
		assert.Equal(t, expectedError, err)
	}
}

func TestModuleGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	var expectedResult api.EventSummaryRepresentation
	var expectedError error = errorhandler.CreateMissingParameterError("")
	var rows sql.Rows
	dbEvents.EXPECT().Query(gomock.Any()).Return(&rows, expectedError).Times(1)
	res, err := module.GetEventsSummary(context.Background())

	assert.Equal(t, expectedResult, res)
	assert.Equal(t, expectedError, err)
}

func TestModuleGetTotalConnectionsCount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	// Check SQL injection
	{
		_, err := module.GetTotalConnectionsCount(context.TODO(), "realm", "1 DAY'; TRUNCATE TABLE PASSWORD; select '")
		assert.NotNil(t, err)
	}
}

func TestCreateStats(t *testing.T) {
	assert.Equal(t, [][]int64{{3, 0}, {2, 0}, {9, 0}, {8, 0}, {7, 0}}, createStats(5, 3, 2, 9, true))
	assert.Equal(t, [][]int64{{7, 0}, {8, 0}, {9, 0}, {2, 0}, {3, 0}}, createStats(5, 3, 2, 9, false))
}
