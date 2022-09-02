package keycloakb

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestStoreOrUpdateUserDetails(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockCrypter = mock.NewEncrypterDecrypter(mockCtrl)
	var encryptedContent = []byte("enc_content")
	var keyID = "KBA_1"

	var userID = "123789"
	t.Run("Update succesful", func(t *testing.T) {

		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), keyID, gomock.Any(), keyID).Return(nil, nil).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyID).Times(1)
		var err = configDBModule.StoreOrUpdateUserDetails(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Nil(t, err)
	})
	t.Run("Update user: error at encryption", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var err = configDBModule.StoreOrUpdateUserDetails(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Equal(t, unexpectedError, err)
	})
	t.Run("Update user: DB error", func(t *testing.T) {
		var unexpectedError = errors.New("error")
		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), keyID, gomock.Any(), keyID).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyID).Times(1)
		var err = configDBModule.StoreOrUpdateUserDetails(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Equal(t, unexpectedError, err)
	})

}

func TestGetUserDB(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockCrypter = mock.NewEncrypterDecrypter(mockCtrl)

	var realm = "my-realm"
	var userID = "user-id"
	var ctx = context.TODO()

	t.Run("Select: unexpected error", func(t *testing.T) {
		var unexpectedError = errors.New("unexpected")
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(unexpectedError)

		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var _, err = configDBModule.GetUserDetails(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Select: NOT FOUND", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)

		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var user, err = configDBModule.GetUserDetails(ctx, realm, userID)
		assert.Nil(t, err)
		assert.NotNil(t, user)
	})
	t.Run("Select: decryption error", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptr = dest[0].(*[]byte)
			*ptr = []byte(`random`)
			return nil
		})
		mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var _, err = configDBModule.GetUserDetails(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Select successful", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptr = dest[0].(*[]byte)
			*ptr = []byte(`random`)
			return nil
		})
		mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).Return([]byte(`{"birth_location": "Antananarivo"}`), nil).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var user, err = configDBModule.GetUserDetails(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Equal(t, "Antananarivo", *user.BirthLocation)
	})
}
