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

func ptr(value string) *string {
	return &value
}

func toJSONString(value interface{}) string {
	var jsonConfBytes, _ = json.Marshal(value)
	return string(jsonConfBytes)
}

func TestGetConfigurations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var realmID = "myrealm"
	var expectedError = errors.New("sql")
	var expectedRealmConf = configuration.RealmConfiguration{BarcodeType: ptr("value")}
	var expectedRealmAdminConf = configuration.RealmAdminConfiguration{Mode: ptr("trustID")}

	t.Run("No error", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any(), gomock.Any()).DoAndReturn(func(params ...interface{}) error {
			// ptrConfJSON *string, ptrAdminConfJSON *string
			*(params[0].(*string)) = toJSONString(expectedRealmConf)
			*(params[1].(*string)) = toJSONString(expectedRealmAdminConf)
			return nil
		})
		realmConf, realmAdminConf, err := configDBModule.GetConfigurations(context.TODO(), realmID)
		assert.Nil(t, err)
		assert.Equal(t, expectedRealmConf, realmConf)
		assert.Equal(t, expectedRealmAdminConf, realmAdminConf)
	})

	t.Run("SQL not found", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any(), gomock.Any()).Return(sql.ErrNoRows)
		_, _, err := configDBModule.GetConfigurations(context.TODO(), realmID)
		assert.NotNil(t, err)
		assert.True(t, strings.Contains(err.Error(), msg.MsgErrNotConfigured))
	})

	t.Run("Unexpected SQL error", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any(), gomock.Any()).Return(expectedError)
		_, _, err := configDBModule.GetConfigurations(context.TODO(), realmID)
		assert.Equal(t, expectedError, err)
	})
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

	t.Run("No error", func(t *testing.T) {
		var expectedResult = configuration.RealmConfiguration{DefaultRedirectURI: ptr("dummy://path/to/nothing")}
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(ptrJSON *string) error {
			*ptrJSON = toJSONString(expectedResult)
			return nil
		})
		result, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.Nil(t, err)
		assert.Equal(t, expectedResult, result)
	})

	t.Run("SQL not found", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		_, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.NotNil(t, err)
		assert.True(t, strings.Contains(err.Error(), msg.MsgErrNotConfigured))
	})

	t.Run("Unexpected SQL error", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(expectedError)
		_, err := configDBModule.GetConfiguration(context.TODO(), realmID)
		assert.Equal(t, expectedError, err)
	})
}

func TestStoreOrGetAdminConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var realmID = "myrealm"
	var adminConfig configuration.RealmAdminConfiguration
	var adminConfigStr = toJSONString(adminConfig)
	var sqlError = errors.New("sql")
	var ctx = context.TODO()

	t.Run("Store-SQL fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, sqlError)
		assert.Equal(t, sqlError, configDBModule.StoreOrUpdateAdminConfiguration(ctx, realmID, adminConfig))
	})
	t.Run("Store-success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil)
		assert.Nil(t, configDBModule.StoreOrUpdateAdminConfiguration(ctx, realmID, adminConfig))
	})
	t.Run("Get-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
		var _, err = configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.Equal(t, sqlError, err)
	})

	t.Run("Get-SQL query returns no row", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		var _, err = configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.NotNil(t, err)
	})

	t.Run("Get-SQL query returns an admin configuration", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(conf *string) error {
			*conf = adminConfigStr
			return nil
		})
		var conf, err = configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.Nil(t, err)
		assert.Equal(t, adminConfig, conf)
	})
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
		mockSQLRows.EXPECT().Close()
		var conf, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Nil(t, err)
		assert.Len(t, conf, 0)
	})
	t.Run("GET-Scan fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any()).Return(expectedError)
		mockSQLRows.EXPECT().Close()
		var _, err = configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("GET-Scan ok", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(params ...interface{}) error {
				// confType *string, realm *string, group *string
				*(params[0].(*string)) = "a"
				*(params[1].(*string)) = "b"
				*(params[2].(*string)) = "c"
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(params ...interface{}) error {
				// confType *string, realm *string, group *string
				*(params[0].(*string)) = "a"
				*(params[1].(*string)) = "b"
				*(params[2].(*string)) = "d"
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(false),
			mockSQLRows.EXPECT().Close(),
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

func TestAuthorization(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRows = mock.NewSQLRows(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var expectedError = errors.New("error")
	var sqlError = errors.New("sql")
	var realmID = "my-realm"
	var groupName = "my-group"
	var targetRealmID = "the-realm"
	var targetGroupName = "the-group"
	var action = "ActionTest"
	var ctx = context.TODO()

	expectedAuthz := configuration.Authorization{
		RealmID:         &realmID,
		GroupName:       &groupName,
		Action:          &action,
		TargetRealmID:   &targetRealmID,
		TargetGroupName: &targetGroupName,
	}

	t.Run("Get-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, targetGroupName).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, targetGroupName, action)
		assert.False(t, res)
		assert.NotNil(t, err)
	})
	t.Run("Get-SQL query returns no row", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, targetGroupName).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, targetGroupName, action)
		assert.False(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL query succeeds", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, targetGroupName).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(nil)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, targetGroupName, action)
		assert.True(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL authorization for action query fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realmID, groupName, action).Return(mockSQLRows, sqlError)
		var _, err = configDBModule.GetAuthorizationsForAction(ctx, realmID, groupName, action)
		assert.Equal(t, sqlError, err)
	})
	t.Run("Get-SQL authorization for action query returns no row", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realmID, groupName, action).Return(mockSQLRows, sql.ErrNoRows)
		var _, err = configDBModule.GetAuthorizationsForAction(ctx, realmID, groupName, action)
		assert.NotNil(t, err)
	})

	t.Run("Get-SQL authorization for action scan fail", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realmID, groupName, action).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(sqlError)
		mockSQLRows.EXPECT().Close().Return(nil)

		var _, err = configDBModule.GetAuthorizationsForAction(ctx, realmID, groupName, action)
		assert.Equal(t, sqlError, err)
	})

	t.Run("Get-SQL authorization for action query returns authorization", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realmID, groupName, action).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(params ...interface{}) error {
				*(params[0].(*string)) = realmID
				*(params[1].(*string)) = groupName
				*(params[2].(*string)) = action
				*(params[3].(*sql.NullString)) = sql.NullString{String: targetRealmID, Valid: true}
				*(params[4].(*sql.NullString)) = sql.NullString{String: targetGroupName, Valid: true}

				return nil
			})
		mockSQLRows.EXPECT().Next().Return(false)
		mockSQLRows.EXPECT().Close().Return(nil)

		var authz, err = configDBModule.GetAuthorizationsForAction(ctx, realmID, groupName, action)
		assert.Nil(t, err)
		assert.Len(t, authz, 1)
		assert.Equal(t, *expectedAuthz.RealmID, *authz[0].RealmID)
		assert.Equal(t, *expectedAuthz.GroupName, *authz[0].GroupName)
		assert.Equal(t, *expectedAuthz.Action, *authz[0].Action)
		assert.Equal(t, *expectedAuthz.TargetRealmID, *authz[0].TargetRealmID)
		assert.Equal(t, *expectedAuthz.TargetGroupName, *authz[0].TargetGroupName)
	})

	t.Run("DELETE-Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, targetGroupName).Return(nil, expectedError)
		var err = configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, targetGroupName, action)
		assert.Equal(t, expectedError, err)
	})

	t.Run("DELETE-Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, targetGroupName).Return(nil, nil)
		var err = configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, targetGroupName, action)
		assert.Nil(t, err)
	})

	t.Run("DELETE global -Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, expectedError)
		var err = configDBModule.DeleteGlobalAuthorization(ctx, realmID, groupName, targetRealmID, action)
		assert.Equal(t, expectedError, err)
	})

	t.Run("DELETE global -Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, nil)
		var err = configDBModule.DeleteGlobalAuthorization(ctx, realmID, groupName, targetRealmID, action)
		assert.Nil(t, err)
	})
}
