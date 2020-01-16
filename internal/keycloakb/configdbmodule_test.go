package keycloakb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/database/sqltypes"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func useMockDB(t *testing.T, fn func(sqltypes.CloudtrustDB)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	fn(mock.NewCloudtrustDB(mockCtrl))
}

func TestConfigurationDBModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockLogger = log.NewNopLogger()

	mockDB.EXPECT().Exec(gomock.Any(), "realmId", gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	var configDBModule = NewConfigurationDBModule(mockDB, mockLogger)
	var err = configDBModule.StoreOrUpdate(context.Background(), "realmId", dto.RealmConfiguration{})
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
		var expectedResult = dto.RealmConfiguration{DefaultRedirectURI: &dummyURL}
		var jsonBytes, _ = json.Marshal(expectedResult)
		var json = string(jsonBytes)
		mockDB.EXPECT().QueryRow(gomock.Any(), realmID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptrJSON = dest[0].(*string)
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
