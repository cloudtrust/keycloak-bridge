package events

//go:generate mockgen -destination=./mock/dbevents.go -package=mock -mock_names=DBEvents=DBEvents github.com/cloudtrust/keycloak-bridge/pkg/events DBEvents

import (
	"context"
	"database/sql"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestModuleGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewDBEvents(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	params := initMap("origin", "origin-1", "max", "5")
	var expectedResult []api.AuditRepresentation
	var expectedError error = keycloakb.CreateMissingParameterError("")
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
	module := NewEventsDBModule(dbEvents)

	var expectedResult api.EventSummaryRepresentation
	var expectedError error = keycloakb.CreateMissingParameterError("")
	var rows sql.Rows
	dbEvents.EXPECT().Query(gomock.Any()).Return(&rows, expectedError).Times(1)
	res, err := module.GetEventsSummary(context.Background())

	assert.Equal(t, expectedResult, res)
	assert.Equal(t, expectedError, err)
}
