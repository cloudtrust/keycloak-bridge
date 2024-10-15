package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
)

func TestStoreUserDetails(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockDB := mock.NewCloudtrustDB(mockCtrl)
	mockCrypter := mock.NewEncrypterDecrypter(mockCtrl)

	archiveModule := NewArchiveDBModule(mockDB, mockCrypter, log.NewNopLogger())

	realmID := "my-realm"
	userID := "123456-789-123-987654"
	user := dto.ArchiveUserRepresentation{ID: &userID}
	userIDBytes := []byte(userID)
	encryptedDetails := []byte("encrypted version of the user details... or not !!??")
	keyID := "KBB_1"
	anyError := errors.New("any error")
	ctx := context.TODO()

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
