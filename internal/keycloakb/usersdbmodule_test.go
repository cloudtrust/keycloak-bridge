package keycloakb

import (
	"context"
	"database/sql"
	"encoding/base64"
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
	var keyId = "KBA_1"

	var userID = "123789"
	t.Run("Update succesful", func(t *testing.T) {

		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), keyId, gomock.Any(), keyId).Return(nil, nil).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyId).Times(1)
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
		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), keyId, gomock.Any(), keyId).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyId).Times(1)
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

func TestGetUserInformation(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRows = mock.NewSQLRows(mockCtrl)
	var mockCrypter = mock.NewEncrypterDecrypter(mockCtrl)
	var usersDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())

	var realm = "my-realm"
	var userID = "user-id"
	var ctx = context.TODO()
	var unexpectedError = errors.New("unexpected")

	t.Run("Unexpected error", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, unexpectedError)

		var _, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("No row", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, sql.ErrNoRows)

		var checks, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Nil(t, checks)
	})

	t.Run("Can't fetch result", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any()).Return(unexpectedError)
		mockSQLRows.EXPECT().Close()

		var _, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Error at decryption", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(params ...interface{}) error {
				// _, _, _, _, _, _, _, _, _ interface{}, proofData *[]byte, _ interface{}
				*(params[9].(*[]byte)) = []byte("ABC")
				return nil
			}),
			mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, unexpectedError),
			mockSQLRows.EXPECT().Close(),
		)

		var _, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Success - without dataproof", func(t *testing.T) {
		var natureValue = "nature"
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(params ...interface{}) error {
				// checkID, realm, userID, operator, datetime, status, checkType, nature (*sql.NullString), proofType, proofData, comment
				*(params[7].(*sql.NullString)) = sql.NullString{Valid: true, String: natureValue}
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(false),
			mockSQLRows.EXPECT().Close(),
		)

		var checks, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Len(t, checks, 1)
		assert.Equal(t, natureValue, *checks[0].Nature)

	})

	t.Run("Success - with dataproof", func(t *testing.T) {
		var natureValue = "nature"
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(params ...interface{}) error {
				// checkID, realm, userID, operator, datetime, status, checkType, nature (*sql.NullString), proofType, proofData, comment
				*(params[7].(*sql.NullString)) = sql.NullString{Valid: true, String: natureValue}
				*(params[9].(*[]byte)) = []byte("ABC")
				return nil
			}),
			mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil),
			mockSQLRows.EXPECT().Next().Return(false),
			mockSQLRows.EXPECT().Close(),
		)

		var checks, err = usersDBModule.GetChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Len(t, checks, 1)
		assert.Equal(t, natureValue, *checks[0].Nature)

	})
}

func TestCreateCheck(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockCrypter = mock.NewEncrypterDecrypter(mockCtrl)

	var userID = "123789"
	var realm = "realm"
	var proofData = []byte(base64.StdEncoding.EncodeToString([]byte("some proof")))
	var encryptedContent = []byte("enc_content")
	var keyId = "KBA_1"

	t.Run("Create check successful", func(t *testing.T) {

		mockDB.EXPECT().Exec(gomock.Any(), realm, userID, gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyId).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Nil(t, err)
	})
	t.Run("Create check: error at encryption", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Equal(t, unexpectedError, err)
	})
	t.Run("Create check: DB error", func(t *testing.T) {
		var unexpectedError = errors.New("error")
		mockDB.EXPECT().Exec(gomock.Any(), realm, userID, gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDetailsDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(encryptedContent, nil).Times(1)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyId).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Equal(t, unexpectedError, err)
	})
}
