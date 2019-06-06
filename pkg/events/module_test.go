package events

import (
	"context"
	"database/sql"
	"testing"

	"github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestModuleGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewDBModule(dbEvents)

	params := initMap("origin", "origin-1", "max", "5")
	var empty [0]api.AuditRepresentation
	var expectedResult = empty[:]
	var expectedError error = http.CreateMissingParameterError("")
	var rows sql.Rows
	dbEvents.EXPECT().Query(gomock.Any(), params["origin"], nil, nil, nil, nil, nil, 0, params["max"]).Return(&rows, expectedError).Times(1)
	res, err := module.GetEvents(context.Background(), params)

	assert.Equal(t, expectedResult, res)
	assert.Equal(t, expectedError, err)
}

func TestModuleGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewDBModule(dbEvents)

	var expectedResult api.EventSummaryRepresentation
	var expectedError error = http.CreateMissingParameterError("")
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
	module := NewDBModule(dbEvents)

	// Check SQL injection
	{
		_, err := module.GetTotalConnectionsCount(context.TODO(), "realm", "1 DAY'; TRUNCATE TABLE PASSWORD; select '")
		assert.NotNil(t, err)
	}
}
