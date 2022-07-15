package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
)

func TestStoreUserDetails(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockDB = mock.NewCloudtrustDB(mockCtrl)
	var mockCrypter = mock.NewEncrypterDecrypter(mockCtrl)

	var archiveModule = NewArchiveDBModule(mockDB, mockCrypter, log.NewNopLogger())

	var realmID = "my-realm"
	var userID = "123456-789-123-987654"
	var user = dto.ArchiveUserRepresentation{ID: &userID}
	var userIDBytes = []byte(userID)
	var encryptedDetails = []byte("encrypted version of the user details... or not !!??")
	var keyID = "KBB_1"
	var anyError = errors.New("any error")
	var ctx = context.TODO()

	t.Run("Encryption fails", func(t *testing.T) {
		mockCrypter.EXPECT().Encrypt(gomock.Any(), userIDBytes).Return(nil, anyError)

		assert.Equal(t, anyError, archiveModule.StoreUserDetails(ctx, realmID, user))
	})

	t.Run("DB insert fails", func(t *testing.T) {
		mockCrypter.EXPECT().Encrypt(gomock.Any(), userIDBytes).Return(encryptedDetails, nil)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyID).Times(1)
		mockDB.EXPECT().Exec(gomock.Any(), realmID, user.ID, encryptedDetails, keyID).Return(nil, anyError)

		assert.Equal(t, anyError, archiveModule.StoreUserDetails(ctx, realmID, user))
	})

	t.Run("DB insert success", func(t *testing.T) {
		mockCrypter.EXPECT().Encrypt(gomock.Any(), userIDBytes).Return(encryptedDetails, nil)
		mockCrypter.EXPECT().GetCurrentKeyID().Return(keyID).Times(1)
		mockDB.EXPECT().Exec(gomock.Any(), realmID, user.ID, encryptedDetails, keyID).Return(nil, nil)

		assert.Nil(t, archiveModule.StoreUserDetails(ctx, realmID, user))
	})
}
