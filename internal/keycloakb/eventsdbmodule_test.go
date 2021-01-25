package keycloakb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/database/sqltypes"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestSelectAuditEventsParameters(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockRow = mock.NewSQLRow(mockCtrl)
	var anyError = errors.New("any error")

	t.Run("Origin only", func(t *testing.T) {
		var origin = "origan"
		filter, err := newSelectAuditEventsParameters(map[string]string{"origin": origin})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), origin, 0, 500).DoAndReturn(func(query string, _, _, _ interface{}) (sqltypes.SQLRows, error) {
			assert.Contains(t, query, " WHERE origin")
			assert.NotContains(t, query, " AND ")
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})
	t.Run("Count with only exclude", func(t *testing.T) {
		var exclude = "excluded"
		filter, err := newSelectAuditEventsParameters(map[string]string{"exclude": exclude})
		assert.Nil(t, err)
		mockDB.EXPECT().QueryRow(gomock.Any(), exclude).DoAndReturn(func(query string, _ interface{}) sqltypes.SQLRow {
			assert.Contains(t, query, " WHERE ct_event_type <>")
			assert.NotContains(t, query, " AND ")
			return mockRow
		})
		var row = filter.queryCount(mockDB)
		assert.Equal(t, mockRow, row)
	})
	t.Run("Limit parameters only", func(t *testing.T) {
		var first = "7777"
		var max = "20"
		filter, err := newSelectAuditEventsParameters(map[string]string{"first": first, "max": max})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), first, max).DoAndReturn(func(query string, _, _ interface{}) (sqltypes.SQLRows, error) {
			assert.NotContains(t, query, "WHERE ")
			assert.NotContains(t, query, " AND ")
			assert.Contains(t, query, "LIMIT ?, ?")
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})
	t.Run("Mix of multiple parameters", func(t *testing.T) {
		var first = "7777"
		var max = "20"
		var ctEventType = "LOGIN"
		var realm = "my-realm"
		filter, err := newSelectAuditEventsParameters(map[string]string{"first": first, "ctEventType": ctEventType, "max": max, "realm": realm})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).DoAndReturn(func(query string, params ...interface{}) (sqltypes.SQLRows, error) {
			assert.Contains(t, query, "WHERE ")
			assert.Contains(t, query, " AND ")
			assert.Contains(t, query, "LIMIT ?, ?")
			assert.Contains(t, params, realm)
			assert.Contains(t, params, ctEventType)
			assert.Equal(t, first, params[2])
			assert.Equal(t, max, params[3])
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})

	var fromDate = "2007-11-03 01:18:00"
	var toDate = "2017-01-31 23:48:00"
	var date1, _ = time.Parse(sqlDateFormat, fromDate)
	var date2, _ = time.Parse(sqlDateFormat, toDate)
	var strDate1 = fmt.Sprintf("%d", date1.Unix())
	var strDate2 = fmt.Sprintf("%d", date2.Unix())

	t.Run("Date from", func(t *testing.T) {
		filter, err := newSelectAuditEventsParameters(map[string]string{"dateFrom": strDate1})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), fromDate, 0, 500).DoAndReturn(func(query string, _, _, _ interface{}) (sqltypes.SQLRows, error) {
			assert.NotContains(t, query, "BETWEEN")
			assert.NotContains(t, query, "<=")
			assert.Contains(t, query, ">=")
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})
	t.Run("Date to", func(t *testing.T) {
		filter, err := newSelectAuditEventsParameters(map[string]string{"dateTo": strDate2})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), toDate, 0, 500).DoAndReturn(func(query string, _, _, _ interface{}) (sqltypes.SQLRows, error) {
			assert.NotContains(t, query, "BETWEEN")
			assert.Contains(t, query, "<=")
			assert.NotContains(t, query, ">=")
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})
	t.Run("Date range", func(t *testing.T) {
		filter, err := newSelectAuditEventsParameters(map[string]string{"dateFrom": strDate1, "dateTo": strDate2})
		assert.Nil(t, err)
		mockDB.EXPECT().Query(gomock.Any(), fromDate, toDate, 0, 500).DoAndReturn(func(query string, _, _, _, _ interface{}) (sqltypes.SQLRows, error) {
			assert.Contains(t, query, "BETWEEN")
			assert.NotContains(t, query, "<=")
			assert.NotContains(t, query, ">=")
			return nil, anyError
		})
		_, err = filter.queryRows(mockDB)
		assert.Equal(t, anyError, err)
	})
}

func TestModuleGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	var rows sql.Rows
	var expectedError error = errorhandler.CreateMissingParameterError("")

	t.Run("Multiple values for exclude", func(t *testing.T) {
		params := map[string]string{"exclude": "value1,value2"}
		dbEvents.EXPECT().Query(gomock.Any(), "value1", "value2", 0, 500).Return(&rows, expectedError)
		_, err := module.GetEvents(context.Background(), params)

		assert.Equal(t, expectedError, err)
	})
	t.Run("Basic query", func(t *testing.T) {
		params := map[string]string{"origin": "origin-1", "max": "5"}
		var empty [0]api.AuditRepresentation
		var expectedResult = empty[:]
		dbEvents.EXPECT().Query(gomock.Any(), params["origin"], 0, params["max"]).Return(&rows, expectedError)
		res, err := module.GetEvents(context.Background(), params)

		assert.Equal(t, expectedResult, res)
		assert.Equal(t, expectedError, err)
	})
}

func TestModuleGetEventsCount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	{
		params := map[string]string{"origin": "origin-1", "max": "5"}
		var expectedResult = 0
		var row sql.Rows
		dbEvents.EXPECT().QueryRow(gomock.Any(), params["origin"]).Return(&row).Times(1)
		res, _ := module.GetEventsCount(context.Background(), params)

		assert.Equal(t, expectedResult, res)
		assert.NotNil(t, res)
	}
}

func TestModuleGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
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

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
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
