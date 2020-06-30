package keycloakb

import (
	"context"
	"database/sql"
	"encoding/base64"
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
	var mockCrypter = mock.NewCrypterDecrypter(mockCtrl)

	var userID = "123789"
	t.Run("Update succesful", func(t *testing.T) {

		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var err = configDBModule.StoreOrUpdateUser(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Nil(t, err)
	})
	t.Run("Update user: error at encryption", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var err = configDBModule.StoreOrUpdateUser(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Equal(t, unexpectedError, err)
	})
	t.Run("Update user: DB error", func(t *testing.T) {
		var unexpectedError = errors.New("error")
		mockDB.EXPECT().Exec(gomock.Any(), "realmId", &userID, gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var err = configDBModule.StoreOrUpdateUser(context.Background(), "realmId", dto.DBUser{UserID: &userID})
		assert.Equal(t, unexpectedError, err)
	})

}

func TestGetUserDB(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRow = mock.NewSQLRow(mockCtrl)
	var mockCrypter = mock.NewCrypterDecrypter(mockCtrl)

	var realm = "my-realm"
	var userID = "user-id"
	var ctx = context.TODO()

	t.Run("Select: unexpected error", func(t *testing.T) {
		var unexpectedError = errors.New("unexpected")
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(unexpectedError)

		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var _, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Select: NOT FOUND", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).Return(sql.ErrNoRows)

		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var user, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Nil(t, user)
	})
	t.Run("Select: decryption error", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptr = dest[0].(*[]byte)
			*ptr = []byte(`random`)
			return nil
		})
		mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var user, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
		assert.Nil(t, user)
	})

	t.Run("Select successful", func(t *testing.T) {
		mockDB.EXPECT().QueryRow(gomock.Any(), realm, userID).Return(mockSQLRow)
		mockSQLRow.EXPECT().Scan(gomock.Any()).DoAndReturn(func(dest ...interface{}) error {
			var ptr = dest[0].(*[]byte)
			*ptr = []byte(`random`)
			return nil
		})
		mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any()).Return([]byte(`{"birth_location": "Antananarivo"}`), nil).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		var user, err = configDBModule.GetUser(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Equal(t, "Antananarivo", *user.BirthLocation)
	})
}

func TestGetUserInformation(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockSQLRows = mock.NewSQLRows(mockCtrl)
	var mockCrypter = mock.NewCrypterDecrypter(mockCtrl)
	var usersDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())

	var realm = "my-realm"
	var userID = "user-id"
	var ctx = context.TODO()
	var unexpectedError = errors.New("unexpected")

	t.Run("Unexpected error", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, unexpectedError)

		var _, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("No row", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, sql.ErrNoRows)

		var checks, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Nil(t, checks)
	})

	t.Run("Can't fetch result", func(t *testing.T) {
		mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil)
		mockSQLRows.EXPECT().Next().Return(true)
		mockSQLRows.EXPECT().Scan(gomock.Any()).Return(unexpectedError)

		var _, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Error at decryption", func(t *testing.T) {
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(_, _, _, _, _, _, _, _, _ interface{}, proofData *[]byte, _ interface{}) error {
				*proofData = []byte("ABC")
				return nil
			}),
			mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError),
		)

		var _, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Equal(t, unexpectedError, err)
	})

	t.Run("Success - without dataproof", func(t *testing.T) {
		var natureValue = "nature"
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(checkID *int64, realm *string, userID *string, operator *sql.NullString,
				datetime *sql.NullString, status *sql.NullString, checkType *sql.NullString, nature *sql.NullString, proofType *sql.NullString,
				proofData *[]byte, comment *sql.NullString) error {
				*nature = sql.NullString{Valid: true, String: natureValue}
				return nil
			}),
			mockSQLRows.EXPECT().Next().Return(false),
		)

		var checks, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Len(t, checks, 1)
		assert.Equal(t, natureValue, *checks[0].Nature)

	})

	t.Run("Success - with dataproof", func(t *testing.T) {
		var natureValue = "nature"
		gomock.InOrder(
			mockDB.EXPECT().Query(gomock.Any(), realm, userID).Return(mockSQLRows, nil),
			mockSQLRows.EXPECT().Next().Return(true),
			mockSQLRows.EXPECT().Scan(gomock.Any()).DoAndReturn(func(checkID *int64, realm *string, userID *string, operator *sql.NullString,
				datetime *sql.NullString, status *sql.NullString, checkType *sql.NullString, nature *sql.NullString, proofType *sql.NullString,
				proofData *[]byte, comment *sql.NullString) error {
				*nature = sql.NullString{Valid: true, String: natureValue}
				*proofData = []byte("ABC")
				return nil
			}),
			mockCrypter.EXPECT().Decrypt(gomock.Any(), gomock.Any()).Return(nil, nil),
			mockSQLRows.EXPECT().Next().Return(false),
		)

		var checks, err = usersDBModule.GetUserChecks(ctx, realm, userID)
		assert.Nil(t, err)
		assert.Len(t, checks, 1)
		assert.Equal(t, natureValue, *checks[0].Nature)

	})
}

func TestCreateCheck(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockCrypter = mock.NewCrypterDecrypter(mockCtrl)

	var userID = "123789"
	var realm = "realm"
	var proofData = []byte(base64.StdEncoding.EncodeToString([]byte("some proof")))
	t.Run("Create check successful", func(t *testing.T) {

		mockDB.EXPECT().Exec(gomock.Any(), realm, userID, gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Nil(t, err)
	})
	t.Run("Create check: error at encryption", func(t *testing.T) {
		var unexpectedError = errors.New("incorrect key")
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Equal(t, unexpectedError, err)
	})
	t.Run("Create check: DB error", func(t *testing.T) {
		var unexpectedError = errors.New("error")
		mockDB.EXPECT().Exec(gomock.Any(), realm, userID, gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, unexpectedError).Times(1)
		var configDBModule = NewUsersDBModule(mockDB, mockCrypter, log.NewNopLogger())
		mockCrypter.EXPECT().Encrypt(gomock.Any(), gomock.Any()).Return(nil, nil).Times(1)
		var err = configDBModule.CreateCheck(context.Background(), realm, userID, dto.DBCheck{ProofData: &proofData})
		assert.Equal(t, unexpectedError, err)
	})
}
