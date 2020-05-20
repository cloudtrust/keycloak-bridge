package keycloakb

import (
	"context"
	"errors"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/errors"
	mock "github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestModuleGetEvents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
	mockRows := mock.NewSQLRows(mockCtrl)
	module := NewEventsDBModule(dbEvents)
	params := map[string]string{"origin": "origin-1", "max": "5"}

	t.Run("Multiple values not yet supported for exclude", func(t *testing.T) {
		params := map[string]string{"exclude": "value1,value2"}
		_, err := module.GetEvents(context.Background(), params)

		assert.NotNil(t, err)
	})
	t.Run("Query fails", func(t *testing.T) {
		var expectedError error = errors.New("query fails")
		dbEvents.EXPECT().Query(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		_, err := module.GetEvents(context.Background(), params)

		assert.Equal(t, expectedError, err)
	})
	t.Run("Scan fails", func(t *testing.T) {
		var scanError = errors.New("scan fails")
		dbEvents.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockRows, nil)
		mockRows.EXPECT().Next().Return(true)
		mockRows.EXPECT().Scan(gomock.Any()).Return(scanError)
		mockRows.EXPECT().Close()
		_, err := module.GetEvents(context.Background(), params)

		assert.Equal(t, scanError, err)
	})
	t.Run("Success", func(t *testing.T) {
		gomock.InOrder(
			dbEvents.EXPECT().Query(gomock.Any(), params["origin"], params["origin"], nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 0, params["max"]).Return(mockRows, nil),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any()).Return(nil),
			mockRows.EXPECT().Next().Return(false),
			mockRows.EXPECT().Err().Return(nil),
			mockRows.EXPECT().Close(),
		)
		res, err := module.GetEvents(context.Background(), params)

		assert.Nil(t, err)
		assert.Len(t, res, 1)
	})
}

func TestModuleGetEventsCount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
	mockRow := mock.NewSQLRow(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	params := map[string]string{"origin": "origin-1", "max": "5"}

	t.Run("Invalid exclude", func(t *testing.T) {
		invalidParams := map[string]string{"origin": "origin-1", "max": "5", "exclude": "value1,value7"}
		_, err := module.GetEventsCount(context.Background(), invalidParams)
		assert.NotNil(t, err)
	})
	t.Run("SQL query fails", func(t *testing.T) {
		var sqlError = errors.New("sql error")
		dbEvents.EXPECT().QueryRow(gomock.Any(), gomock.Any()).Return(mockRow)
		mockRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
		_, err := module.GetEventsCount(context.Background(), params)

		assert.Equal(t, sqlError, err)
	})
	t.Run("Success", func(t *testing.T) {
		var expectedResult = 158
		dbEvents.EXPECT().QueryRow(gomock.Any(), params["origin"], params["origin"], nil, nil, nil, nil, nil, nil, nil, nil, nil, nil).Return(mockRow)
		mockRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(value *int) error {
			*value = expectedResult
			return nil
		})
		res, err := module.GetEventsCount(context.Background(), params)

		assert.Nil(t, err)
		assert.Equal(t, expectedResult, res)
	})
}

func TestModuleGetEventsSummary(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	dbEvents := mock.NewCloudtrustDB(mockCtrl)
	mockRows := mock.NewSQLRows(mockCtrl)
	module := NewEventsDBModule(dbEvents)

	var expectedError error = errorhandler.CreateMissingParameterError("")

	t.Run("First query fails", func(t *testing.T) {
		dbEvents.EXPECT().Query(gomock.Any()).Return(nil, expectedError).Times(1)
		_, err := module.GetEventsSummary(context.Background())

		assert.Equal(t, expectedError, err)
	})
	t.Run("Second query fails", func(t *testing.T) {
		dbEvents.EXPECT().Query(gomock.Any()).Return(mockRows, nil)
		mockRows.EXPECT().Next().Return(false)
		mockRows.EXPECT().Close()
		dbEvents.EXPECT().Query(gomock.Any()).Return(nil, expectedError)
		_, err := module.GetEventsSummary(context.Background())

		assert.Equal(t, expectedError, err)
	})
	t.Run("Third query fails", func(t *testing.T) {
		dbEvents.EXPECT().Query(gomock.Any()).Return(mockRows, nil).Times(2)
		mockRows.EXPECT().Next().Return(false).Times(2)
		mockRows.EXPECT().Close().Times(2)
		dbEvents.EXPECT().Query(gomock.Any()).Return(nil, expectedError)
		_, err := module.GetEventsSummary(context.Background())

		assert.Equal(t, expectedError, err)
	})
	t.Run("Success", func(t *testing.T) {
		gomock.InOrder(
			dbEvents.EXPECT().Query(gomock.Any()).Return(mockRows, nil),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(value *string) error {
				*value = "realm"
				return nil
			}),
			mockRows.EXPECT().Next().Return(false),
			mockRows.EXPECT().Close(),
			dbEvents.EXPECT().Query(gomock.Any()).Return(mockRows, nil),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(value *string) error {
				*value = "origin"
				return nil
			}),
			mockRows.EXPECT().Next().Return(false),
			mockRows.EXPECT().Close(),
			dbEvents.EXPECT().Query(gomock.Any()).Return(mockRows, nil),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(value *string) error {
				*value = "event"
				return nil
			}),
			mockRows.EXPECT().Next().Return(false),
			mockRows.EXPECT().Close(),
		)
		res, err := module.GetEventsSummary(context.Background())

		assert.Nil(t, err)
		assert.Equal(t, []string{"realm"}, res.Realms)
		assert.Equal(t, []string{"origin"}, res.Origins)
		assert.Equal(t, []string{"event"}, res.CtEventTypes)
	})
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

func TestModuleGetUsersLastLogin(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockRows := mock.NewSQLRows(mockCtrl)
	module := NewEventsDBModule(mockDB)

	var realmName = "my-realm"

	t.Run("Query fails", func(t *testing.T) {
		var sqlError = errors.New("Query fails")
		mockDB.EXPECT().Query(gomock.Any(), realmName).Return(nil, sqlError)
		var _, err = module.GetUsersLastLogin(nil, realmName)

		assert.Equal(t, sqlError, err)
	})
	t.Run("Scan fails", func(t *testing.T) {
		var sqlError = errors.New("Scan fails")
		mockDB.EXPECT().Query(gomock.Any(), realmName).Return(mockRows, nil)
		mockRows.EXPECT().Next().Return(true)
		mockRows.EXPECT().Scan(gomock.Any(), gomock.Any()).Return(sqlError)
		mockRows.EXPECT().Close()
		var _, err = module.GetUsersLastLogin(nil, realmName)

		assert.Equal(t, sqlError, err)
	})
	t.Run("Success", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realmName).Return(mockRows, nil),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(func(uid *string, last *int64) error {
				*uid = "user#111111"
				*last = int64(111111)
				return nil
			}),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(func(uid *string, last *int64) error {
				*uid = "user#222222"
				*last = int64(222222)
				return nil
			}),
			mockRows.EXPECT().Next().Return(true),
			mockRows.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(func(uid *string, last *int64) error {
				*uid = "user#333333"
				*last = int64(333333)
				return nil
			}),
			mockRows.EXPECT().Next().Return(false),
			mockRows.EXPECT().Close(),
		)
		var res, err = module.GetUsersLastLogin(nil, realmName)

		assert.Nil(t, err)
		assert.Len(t, res, 3)
		assert.Equal(t, int64(111111000), res["user#111111"])
		assert.Equal(t, int64(222222000), res["user#222222"])
		assert.Equal(t, int64(333333000), res["user#333333"])
	})
}

func TestCreateStats(t *testing.T) {
	assert.Equal(t, [][]int64{{3, 0}, {2, 0}, {9, 0}, {8, 0}, {7, 0}}, createStats(5, 3, 2, 9, true))
	assert.Equal(t, [][]int64{{7, 0}, {8, 0}, {9, 0}, {2, 0}, {3, 0}}, createStats(5, 3, 2, 9, false))
}
