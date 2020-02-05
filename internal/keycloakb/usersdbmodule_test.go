package keycloakb

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestStoreOrUpdateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)

	var userID = "123789"
	mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
	var configDBModule = NewUsersDBModule(mockDB, log.NewNopLogger())
	var err = configDBModule.StoreOrUpdateUser(context.Background(), "realmId", dto.DBUser{UserID: &userID})
	assert.Nil(t, err)
}

func TestGetUserDB(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)

	var realm = "my-realm"
	var userID = "user-id"
	var ctx = context.TODO()

	t.Run("Select: unexpected error", func(t *testing.T) {
		var unexpectedError = errors.New("unexpected")
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(unexpectedError)

		var configDBModule = NewUsersDBModule(mockDB, log.NewNopLogger())
		var _, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Select: NOT FOUND", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)

		var configDBModule = NewUsersDBModule(mockDB, log.NewNopLogger())
		var user, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Nil(t, user)
	})

	t.Run("Select successful", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptr = dest[0].(*string)
			*ptr = `{"birth_location": "Antananarivo"}`
			return nil
		})

		var configDBModule = NewUsersDBModule(mockDB, log.NewNopLogger())
		var user, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Equal(t, "Antananarivo", *user.BirthLocation)
	})
}
