package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/log"

	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestConfigurationDBModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockLogger = log.NewNopLogger()

	mockDB.EXPECT().Exec(gomock.Any(), "realmId", gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var err = configDBModule.StoreOrUpdateConfiguration(context.Background(), "realmId", configuration.RealmConfiguration{})
	assert.Nil(t, err)
}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var realmID = "myrealm"
	var expectedError = errors.New("sql")

	{
		// No error
		var dummyURL = "dummy://path/to/nothing"
		var expectedResult = configuration.RealmConfiguration{DefaultRedirectURI: &dummyURL}
		var jsonBytes, _ = json.Marshal(expectedResult)
		var json = string(jsonBytes)
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(ptrJSON *string) error {
			*ptrJSON = json
			return nil
		})
		result, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.Nil(t, err)
		assert.Equal(t, expectedResult, result)
	}

	{
		// SQL not found
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		_, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.NotNil(t, err)
		assert.True(t, strings.Contains(err.Error(), msg.MsgErrNotConfigured))
	}

	{
		// Unexpected SQL error
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(expectedError)
		_, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.Equal(t, expectedError, err)
	}
}

func TestBackOfficeConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRows = mock.NewSQLRows(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var expectedError = errors.New("error")
	var realmID = "my-realm"
	var groupName = "my-group"
	var confType = "customers"
	var targetRealmID = "the-realm"
	var targetGroupName = "the-group"
	var groupNames = []string{"group1", "group2"}
	var ctx = context.TODO()

	t.Run("GET-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		var _, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("GET-SQLRows is empty", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(false)
		var conf, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Nil(t, err)
		assert.Len(t, conf, 0)
	})
	t.Run("GET-Scan fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any()).Return(expectedError)
		var _, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("GET-Scan ok", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(confType *string, realm *string, group *string) error {
				*confType = "a"
				*realm = "b"
				*group = "c"
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(confType *string, realm *string, group *string) error {
				*confType = "a"
				*realm = "b"
				*group = "d"
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(false),
		)
		var conf, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Nil(t, err)
		assert.Equal(t, []string{"c", "d"}, conf["a"]["b"])
	})

	t.Run("DELETE-Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		var err = configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, &targetRealmID, &targetGroupName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("DELETE-Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil)
		var err = configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, &targetRealmID, &targetGroupName)
		assert.Nil(t, err)
	})

	t.Run("INSERT-Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		var err = configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("INSERT-Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil).Times(len(groupNames))
		var err = configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, groupNames)
		assert.Nil(t, err)
	})
}
