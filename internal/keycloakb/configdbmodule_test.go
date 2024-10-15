package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"

	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestConfigurationDBModule(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockLogger := log.NewNopLogger()

	mockDB.EXPECT().Exec(gomock.Any(), "realmId", gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	err := configDBModule.StoreOrUpdateConfiguration(context.Background(), "realmId", configuration.RealmConfiguration{})
	assert.Nil(t, err)
}

func toJSONString(value interface{}) string {
	jsonConfBytes, _ := json.Marshal(value)
	return string(jsonConfBytes)
}

func TestGetConfigurations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRow := mock.NewSQLRow(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	realmID := "myrealm"
	expectedError := errors.New("sql")
	expectedRealmConf := configuration.RealmConfiguration{BarcodeType: ptr("value")}
	expectedRealmAdminConf := configuration.RealmAdminConfiguration{Mode: ptr("trustID")}

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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRow := mock.NewSQLRow(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	realmID := "myrealm"
	expectedError := errors.New("sql")

	t.Run("No error", func(t *testing.T) {
		expectedResult := configuration.RealmConfiguration{DefaultRedirectURI: ptr("dummy://path/to/nothing")}
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRow := mock.NewSQLRow(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	realmID := "myrealm"
	var adminConfig configuration.RealmAdminConfiguration
	adminConfigStr := toJSONString(adminConfig)
	sqlError := errors.New("sql")
	ctx := context.TODO()

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
		_, err := configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.Equal(t, sqlError, err)
	})

	t.Run("Get-SQL query returns no row", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		_, err := configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.NotNil(t, err)
	})

	t.Run("Get-SQL query returns an admin configuration", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(conf *string) error {
			*conf = adminConfigStr
			return nil
		})
		conf, err := configDBModule.GetAdminConfiguration(ctx, realmID)
		assert.Nil(t, err)
		assert.Equal(t, adminConfig, conf)
	})
}

func TestBackOfficeConfiguration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRows := mock.NewSQLRows(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	expectedError := errors.New("error")
	realmID := "my-realm"
	groupName := "my-group"
	confType := "customers"
	targetRealmID := "the-realm"
	targetGroupName := "the-group"
	groupNames := []string{"group1", "group2"}
	ctx := context.TODO()

	t.Run("GET-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		_, err := configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("GET-SQLRows is empty", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(false)
		mockSQLRows.EXPECT().Close()
		conf, err := configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Nil(t, err)
		assert.Len(t, conf, 0)
	})
	t.Run("GET-Scan fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any()).Return(expectedError)
		mockSQLRows.EXPECT().Close()
		_, err := configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
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
		conf, err := configDBModule.GetBackOfficeConfiguration(ctx, realmID, groupNames)
		assert.Nil(t, err)
		assert.Equal(t, []string{"c", "d"}, conf["a"]["b"])
	})

	t.Run("DELETE-Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		err := configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, &targetRealmID, &targetGroupName)
		assert.Equal(t, expectedError, err)
	})
	t.Run("DELETE-Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil)
		err := configDBModule.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, &targetRealmID, &targetGroupName)
		assert.Nil(t, err)
	})

	t.Run("INSERT-Fails", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, expectedError)
		err := configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, groupNames)
		assert.Equal(t, expectedError, err)
	})
	t.Run("INSERT-Success", func(t *testing.T) {
		mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil).Times(len(groupNames))
		err := configDBModule.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, groupNames)
		assert.Nil(t, err)
	})
}

func TestGetAuthorizations(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRows := mock.NewSQLRows(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	realmID := "my-realm"
	groupName := "my-group"
	sqlError := errors.New("sql")
	ctx := context.TODO()

	t.Run("Call to Query fails", func(t *testing.T) {
		mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(nil, sqlError)
		_, err := configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.NotNil(t, err)
	})
	t.Run("Scan fails", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).Return(sqlError),
			mockSQLRows.EXPECT().Close(),
		)
		_, err := configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).Return(nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).Return(nil),
			mockSQLRows.EXPECT().Next().Return(false),
			mockSQLRows.EXPECT().Close(),
		)
		res, err := configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})
}

func TestAuthorization(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockSQLRow := mock.NewSQLRow(mockCtrl)
	mockLogger := log.NewNopLogger()

	configDBModule := NewConfigurationDBModule(mockDB, mockLogger)
	expectedError := errors.New("error")
	sqlError := errors.New("sql")
	realmID := "my-realm"
	groupName := "my-group"
	targetRealmID := "the-realm"
	targetGroupName := "the-group"
	action := "ActionTest"
	ctx := context.TODO()

	t.Run("Get-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
		res, err := configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.False(t, res)
		assert.NotNil(t, err)
	})
	t.Run("Get-SQL query returns no row", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		res, err := configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.False(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL query succeeds", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(nil)
		res, err := configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.True(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL query succeeds", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(nil)
		res, err := configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, nil, action)
		assert.True(t, res)
		assert.Nil(t, err)
	})

	t.Run("CreateAuthorization", func(t *testing.T) {
		auth := configuration.Authorization{}

		t.Run("Failure", func(t *testing.T) {
			mockDB.EXPECT().Exec(createAuthzStmt, gomock.Any()).Return(nil, sqlError)
			err := configDBModule.CreateAuthorization(ctx, auth)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(createAuthzStmt, gomock.Any()).Return(nil, nil)
			err := configDBModule.CreateAuthorization(ctx, configuration.Authorization{})
			assert.Nil(t, err)
		})
	})

	t.Run("DeleteAuthorization", func(t *testing.T) {
		t.Run("Exec fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(nil, expectedError)
			err := configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success with non nil target group", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(nil, nil)
			err := configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
			assert.Nil(t, err)
		})
		t.Run("Success with nil target group", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, nil)
			err := configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, nil, action)
			assert.Nil(t, err)
		})
	})

	t.Run("DeleteAllAuthorizationsWithGroup", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, realmID, groupName).Return(nil, expectedError)
			err := configDBModule.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, realmID, groupName).Return(nil, nil)
			err := configDBModule.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
			assert.Nil(t, err)
		})
	})

	t.Run("Clean every realms", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action).Return(nil, expectedError)
			err := configDBModule.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupName, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Clean every realms-Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action).Return(nil, nil)
			err := configDBModule.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupName, action)
			assert.Nil(t, err)
		})
	})

	t.Run("Clean realms", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, expectedError)
			err := configDBModule.CleanAuthorizationsActionForRealm(ctx, realmID, groupName, targetRealmID, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, nil)
			err := configDBModule.CleanAuthorizationsActionForRealm(ctx, realmID, groupName, targetRealmID, action)
			assert.Nil(t, err)
		})
	})

	t.Run("NewTransaction", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(nil, expectedError)
			_, err := configDBModule.NewTransaction(ctx)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(nil, nil)
			_, err := configDBModule.NewTransaction(ctx)
			assert.Nil(t, err)
		})
	})
}
