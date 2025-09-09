package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"

	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type dbMocks struct {
	mockCtrl *gomock.Controller
	db       *mock.CloudtrustDB
	sqlRow   *mock.SQLRow
	sqlRows  *mock.SQLRows
	tx       *mock.Transaction
	logger   log.Logger
}

func newDbMocks(t *testing.T) *dbMocks {
	var mockCtrl = gomock.NewController(t)
	return &dbMocks{
		mockCtrl: mockCtrl,
		db:       mock.NewCloudtrustDB(mockCtrl),
		sqlRow:   mock.NewSQLRow(mockCtrl),
		sqlRows:  mock.NewSQLRows(mockCtrl),
		tx:       mock.NewTransaction(mockCtrl),
		logger:   log.NewNopLogger(),
	}
}

func (m *dbMocks) NewConfigurationDBModule(actions ...[]string) ConfigurationDBModule {
	return NewConfigurationDBModule(m.db, m.logger)
}

func (m *dbMocks) Finish() {
	m.mockCtrl.Finish()
}

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
		mockSQLRows.EXPECT().Err()
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
	t.Run("iteration fails", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), gomock.Any()).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(false)
		mockSQLRows.EXPECT().Err().Return(expectedError)
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
			mockSQLRows.EXPECT().Err(),
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

func TestContextKeyConfiguration(t *testing.T) {
	var mocks = newDbMocks(t)
	defer mocks.Finish()

	var customerRealm = "customer-realm"
	var realmContext1 = configuration.RealmContextKey{
		ID:              "uuid1",
		Label:           "label1",
		IdentitiesRealm: "identities-realm",
		Config:          configuration.ContextKeyConfiguration{},
	}
	var contextKeyID = "context-key-id"
	var ctx = context.TODO()

	var module = mocks.NewConfigurationDBModule()

	t.Run("GetAllContextKeyID", func(t *testing.T) {
		t.Run("GetAllContextKeyID query fails", func(t *testing.T) {
			var sqlError = errors.New("SQL error")
			mocks.db.EXPECT().Query(selectAllContextKeyID).Return(nil, sqlError)

			var _, err = module.GetAllContextKeyID(ctx)
			assert.Equal(t, sqlError, err)
		})
		t.Run("Scan fails", func(t *testing.T) {
			var scanError = errors.New("scan error")
			mocks.db.EXPECT().Query(selectAllContextKeyID).Return(mocks.sqlRows, nil)
			mocks.sqlRows.EXPECT().Next().Return(true)
			mocks.sqlRows.EXPECT().Scan(gomock.Any()).Return(scanError)
			mocks.sqlRows.EXPECT().Close()

			var _, err = module.GetAllContextKeyID(ctx)
			assert.Equal(t, scanError, err)
		})
		t.Run("SQL error after fetching all rows", func(t *testing.T) {
			var rowsError = errors.New("scan error")
			mocks.db.EXPECT().Query(selectAllContextKeyID).Return(mocks.sqlRows, nil)
			mocks.sqlRows.EXPECT().Next().Return(false)
			mocks.sqlRows.EXPECT().Err().Return(rowsError)
			mocks.sqlRows.EXPECT().Close()

			var _, err = module.GetAllContextKeyID(ctx)
			assert.Equal(t, rowsError, err)
		})
		t.Run("Success case", func(t *testing.T) {
			gomock.InOrder(
				mocks.db.EXPECT().Query(selectAllContextKeyID).Return(mocks.sqlRows, nil),
				mocks.sqlRows.EXPECT().Next().Return(true),
				mocks.sqlRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(ptr any) error {
					*(ptr.(*string)) = "value"
					return nil
				}),
				mocks.sqlRows.EXPECT().Next().Return(false),
				mocks.sqlRows.EXPECT().Err().Return(nil),
				mocks.sqlRows.EXPECT().Close(),
			)

			var res, err = module.GetAllContextKeyID(ctx)
			assert.Nil(t, err)
			assert.Len(t, res, 1)
			assert.Equal(t, "value", res[0])
		})
	})

	t.Run("Select query fails", func(t *testing.T) {
		var sqlError = errors.New("SQL error")
		mocks.db.EXPECT().Query(gomock.Any(), nil, &customerRealm).Return(nil, sqlError)

		var _, err = module.GetDefaultContextKeyConfiguration(ctx, customerRealm)
		assert.Equal(t, sqlError, err)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("Delete query fails", func(t *testing.T) {
			var deleteError = errors.New("deeelt eorrr")
			mocks.tx.EXPECT().Exec(deleteContextKeyStmt, contextKeyID, customerRealm).Return(nil, deleteError)

			var err = module.DeleteContextKeyConfiguration(ctx, mocks.tx, customerRealm, contextKeyID)
			assert.Equal(t, deleteError, err)
		})
		t.Run("Delete success", func(t *testing.T) {
			mocks.db.EXPECT().Exec(deleteContextKeyStmt, contextKeyID, customerRealm).Return(nil, nil)

			var err = module.DeleteContextKeyConfiguration(ctx, nil, customerRealm, contextKeyID)
			assert.Nil(t, err)
		})
	})

	t.Run("Insert/Update", func(t *testing.T) {
		t.Run("Creation/update failure", func(t *testing.T) {
			var creationError = errors.New("craetoin eorrr")
			mocks.db.EXPECT().Exec(storeContextKeyStmt, gomock.Any()).Return(nil, creationError)

			var err = module.StoreContextKeyConfiguration(ctx, nil, realmContext1)
			assert.Equal(t, creationError, err)
		})
		t.Run("Creation/update success", func(t *testing.T) {
			mocks.tx.EXPECT().Exec(storeContextKeyStmt, gomock.Any()).Return(nil, nil)

			var err = module.StoreContextKeyConfiguration(ctx, mocks.tx, realmContext1)
			assert.Nil(t, err)
		})
	})
}

func TestGetAuthorizations(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRows = mock.NewSQLRows(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var realmID = "my-realm"
	var groupName = "my-group"
	var sqlError = errors.New("sql")
	var ctx = context.TODO()

	t.Run("Call to Query fails", func(t *testing.T) {
		mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(nil, sqlError)
		var _, err = configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.NotNil(t, err)
	})
	t.Run("Scan fails", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).Return(sqlError),
			mockSQLRows.EXPECT().Close(),
		)
		var _, err = configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.NotNil(t, err)
	})
	t.Run("iteration fails", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(selectAuthzStmt, gomock.Any()).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(false),
			mockSQLRows.EXPECT().Err().Return(sqlError),
			mockSQLRows.EXPECT().Close(),
		)
		var _, err = configDBModule.GetAuthorizations(ctx, realmID, groupName)
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
			mockSQLRows.EXPECT().Err(),
			mockSQLRows.EXPECT().Close(),
		)
		var res, err = configDBModule.GetAuthorizations(ctx, realmID, groupName)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})
}

func TestAuthorization(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
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

	t.Run("Get-SQL query fails", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.False(t, res)
		assert.NotNil(t, err)
	})
	t.Run("Get-SQL query returns no row", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.False(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL query succeeds", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(nil)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
		assert.True(t, res)
		assert.Nil(t, err)
	})

	t.Run("Get-SQL query succeeds", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID, groupName, action, targetRealmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(nil)
		var res, err = configDBModule.AuthorizationExists(ctx, realmID, groupName, targetRealmID, nil, action)
		assert.True(t, res)
		assert.Nil(t, err)
	})

	t.Run("CreateAuthorization", func(t *testing.T) {
		var auth = configuration.Authorization{}

		t.Run("Failure", func(t *testing.T) {
			mockDB.EXPECT().Exec(createAuthzStmt, gomock.Any()).Return(nil, sqlError)
			var err = configDBModule.CreateAuthorization(ctx, auth)
			assert.NotNil(t, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(createAuthzStmt, gomock.Any()).Return(nil, nil)
			var err = configDBModule.CreateAuthorization(ctx, configuration.Authorization{})
			assert.Nil(t, err)
		})
	})

	t.Run("DeleteAuthorization", func(t *testing.T) {
		t.Run("Exec fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(nil, expectedError)
			var err = configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success with non nil target group", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID, gomock.Any()).Return(nil, nil)
			var err = configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, &targetGroupName, action)
			assert.Nil(t, err)
		})
		t.Run("Success with nil target group", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, nil)
			var err = configDBModule.DeleteAuthorization(ctx, realmID, groupName, targetRealmID, nil, action)
			assert.Nil(t, err)
		})
	})

	t.Run("DeleteAllAuthorizationsWithGroup", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, realmID, groupName).Return(nil, expectedError)
			var err = configDBModule.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, realmID, groupName).Return(nil, nil)
			var err = configDBModule.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
			assert.Nil(t, err)
		})
	})

	t.Run("Clean every realms", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action).Return(nil, expectedError)
			var err = configDBModule.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupName, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Clean every realms-Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action).Return(nil, nil)
			var err = configDBModule.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupName, action)
			assert.Nil(t, err)
		})
	})

	t.Run("Clean realms", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, expectedError)
			var err = configDBModule.CleanAuthorizationsActionForRealm(ctx, realmID, groupName, targetRealmID, action)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(gomock.Any(), realmID, groupName, action, targetRealmID).Return(nil, nil)
			var err = configDBModule.CleanAuthorizationsActionForRealm(ctx, realmID, groupName, targetRealmID, action)
			assert.Nil(t, err)
		})
	})

	t.Run("NewTransaction", func(t *testing.T) {
		t.Run("Fails", func(t *testing.T) {
			mockDB.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(nil, expectedError)
			var _, err = configDBModule.NewTransaction(ctx)
			assert.Equal(t, expectedError, err)
		})
		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().BeginTx(gomock.Any(), gomock.Any()).Return(nil, nil)
			var _, err = configDBModule.NewTransaction(ctx)
			assert.Nil(t, err)
		})
	})
}

func TestThemeConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockLogger = log.NewNopLogger()
	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)

	var realmName = "my-realm"
	var color = "#13a538"
	var menuTheme = "dark"
	var fontFamily = "Lato"
	var settings = configuration.ThemeConfigurationSettings{
		Color:      &color,
		MenuTheme:  &menuTheme,
		FontFamily: &fontFamily,
	}

	var logo = []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	}
	var favicon = []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	}
	var translationEN = map[string]any{
		"key":     "value",
		"welcome": "Welcome",
	}
	var translationFR = map[string]any{
		"key":     "valeur",
		"welcome": "Bienvenue",
	}
	var translationIT = map[string]any{
		"key":     "valore",
		"welcome": "Benvenuto",
	}
	var translationDE = map[string]any{
		"key":     "wert",
		"welcome": "Willkommen",
	}
	var translations = map[string]any{
		"EN": translationEN,
		"FR": translationFR,
		"IT": translationIT,
		"DE": translationDE,
	}
	var ctx = context.TODO()
	var sqlError = errors.New("sql error")

	t.Run("GetThemeConfiguration", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			var settingsJSON = `{"color":"#13a538","menu_theme":"dark","font_family":"Lato"}`
			mockDB.EXPECT().QueryRow(selectThemeConfigStmt, realmName).Return(mockSQLRow)
			mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(args ...any) error {
				*(args[0].(*[]byte)) = []byte(settingsJSON)
				*(args[1].(*[]byte)) = logo
				*(args[2].(*[]byte)) = favicon
				return nil
			})
			conf, err := configDBModule.GetThemeConfiguration(ctx, realmName)
			assert.Nil(t, err)
			assert.Equal(t, &settings, conf.Settings)
			assert.Equal(t, logo, conf.Logo)
			assert.Equal(t, favicon, conf.Favicon)
		})

		t.Run("Not found", func(t *testing.T) {
			mockDB.EXPECT().QueryRow(selectThemeConfigStmt, realmName).Return(mockSQLRow)
			mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
			_, err := configDBModule.GetThemeConfiguration(ctx, realmName)
			assert.NotNil(t, err)
			assert.True(t, strings.Contains(err.Error(), msg.MsgErrNotConfigured))
		})

		t.Run("SQL error", func(t *testing.T) {
			mockDB.EXPECT().QueryRow(selectThemeConfigStmt, realmName).Return(mockSQLRow)
			mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sqlError)
			_, err := configDBModule.GetThemeConfiguration(ctx, realmName)
			assert.Equal(t, sqlError, err)
		})
	})

	t.Run("UpdateThemeConfiguration", func(t *testing.T) {
		var themeConfig = configuration.ThemeConfiguration{
			RealmName:    ptr(realmName),
			Settings:     &settings,
			Logo:         logo,
			Favicon:      favicon,
			Translations: translations,
		}

		var settingsJSON = `{"color":"#13a538","menu_theme":"dark","font_family":"Lato"}`
		var translationsJSON = `{"DE":{"key":"wert","welcome":"Willkommen"},"EN":{"key":"value","welcome":"Welcome"},"FR":{"key":"valeur","welcome":"Bienvenue"},"IT":{"key":"valore","welcome":"Benvenuto"}}`

		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().Exec(updateThemeConfigStmt, ptr(realmName), settingsJSON, logo, favicon, translationsJSON).Return(nil, nil)
			err := configDBModule.UpdateThemeConfiguration(ctx, themeConfig)
			assert.Nil(t, err)
		})

		t.Run("SQL error", func(t *testing.T) {
			mockDB.EXPECT().Exec(updateThemeConfigStmt, ptr(realmName), settingsJSON, logo, favicon, translationsJSON).Return(nil, sqlError)
			err := configDBModule.UpdateThemeConfiguration(ctx, themeConfig)
			assert.Equal(t, sqlError, err)
		})
	})

	t.Run("GetThemeTranslation", func(t *testing.T) {
		var language = "EN"
		var expectedTranslation = `{"key":"value","welcome":"Welcome"}`

		t.Run("Success", func(t *testing.T) {
			mockDB.EXPECT().QueryRow(gomock.Any(), realmName).Return(mockSQLRow)
			mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest *sql.NullString) error {
				dest.String = expectedTranslation
				dest.Valid = true
				return nil
			})
			translation, err := configDBModule.GetThemeTranslation(ctx, realmName, language)
			assert.Nil(t, err)
			assert.Equal(t, expectedTranslation, translation)
		})

		t.Run("Not found", func(t *testing.T) {
			mockDB.EXPECT().QueryRow(gomock.Any(), realmName).Return(mockSQLRow)
			mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)
			_, err := configDBModule.GetThemeTranslation(ctx, realmName, language)
			assert.Equal(t, errorhandler.Error{
				Status:  404,
				Message: "keycloak-bridge.notConfigured.my-realm.EN",
			}, err)
		})

		t.Run("Different languages", func(t *testing.T) {
			languages := []string{"DE", "FR", "IT"}
			translations := map[string]string{
				"DE": `{"key":"wert","welcome":"Willkommen"}`,
				"FR": `{"key":"valeur","welcome":"Bienvenue"}`,
				"IT": `{"key":"valore","welcome":"Benvenuto"}`,
			}

			for _, lang := range languages {
				mockDB.EXPECT().QueryRow(gomock.Any(), realmName).Return(mockSQLRow)
				mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest *sql.NullString) error {
					dest.String = translations[lang]
					dest.Valid = true
					return nil
				})
				translation, err := configDBModule.GetThemeTranslation(ctx, realmName, lang)
				assert.Nil(t, err)
				assert.Equal(t, translations[lang], translation)
			}
		})
	})
}
