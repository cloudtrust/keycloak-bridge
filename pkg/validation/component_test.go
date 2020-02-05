package validation

import (
	"context"
	"errors"
	"testing"

	log "github.com/cloudtrust/common-service/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/pkg/validation/mock"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createValidUser() apikyc.UserRepresentation {
	var (
		gender        = "M"
		firstName     = "Marc"
		lastName      = "El-Bichoun"
		email         = "marcel.bichon@elca.ch"
		phoneNumber   = "00 33 686 550011"
		birthDate     = "31.03.2001"
		birthLocation = "Montreux"
		docType       = "ID_CARD"
		docNumber     = "MEL123789654ABC"
		docExp        = "28.02.2050"
	)

	return apikyc.UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		EmailAddress:         &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		IDDocumentType:       &docType,
		IDDocumentNumber:     &docNumber,
		IDDocumentExpiration: &docExp,
	}
}

func TestGetUserComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockTokenProvider = mock.NewTokenProvider(mockCtrl)

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var userID = ""

	var ctx = context.Background()

	var component = NewComponent(realm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, log.NewNopLogger())

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		var _, err = component.GetUser(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser from Keycloak fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var kcError = errors.New("kc error")
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, kcError)
		var _, err = component.GetUser(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("GetUser from DB fails", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		var dbError = errors.New("DB error")
		mockUsersDB.EXPECT().GetUser(ctx, realm, userID).Return(&dto.DBUser{}, dbError)
		var _, err = component.GetUser(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("No user found in DB", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDB.EXPECT().GetUser(ctx, realm, userID).Return(nil, nil)
		var _, err = component.GetUser(ctx, userID)
		assert.Nil(t, err)
	})

	t.Run("Happy path", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDB.EXPECT().GetUser(ctx, realm, userID).Return(&dto.DBUser{}, nil)
		var _, err = component.GetUser(ctx, userID)
		assert.Nil(t, err)
	})
}

func TestUpdateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockTokenProvider = mock.NewTokenProvider(mockCtrl)

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var accessToken = "abcdef"
	var ctx = context.TODO()

	var component = NewComponent(targetRealm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, log.NewNopLogger())

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		var user = api.UserRepresentation{}
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("No update needed", func(t *testing.T) {
		var user = api.UserRepresentation{}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var err = component.UpdateUser(ctx, userID, user)
		assert.Nil(t, err)
	})

	t.Run("Fails to get user in KC", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var kcError = errors.New("kc error")
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, kcError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in KC", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var kcError = errors.New("kc error")
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in KC", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		var kcError = errors.New("kc error")
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(kcError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Fails to update user in DB", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		var dbError = errors.New("db error")
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(dbError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Failure to store event", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		var e = errors.New("error")
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(e)
		var err = component.UpdateUser(ctx, userID, user)
		assert.Nil(t, err)
	})

	t.Run("Successful update", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName:      ptr("newFirstname"),
			IDDocumentType: ptr("type"),
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		var err = component.UpdateUser(ctx, userID, user)
		assert.Nil(t, err)
	})
}

func TestCreateCheck(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockUsersDB = mock.NewUsersDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockTokenProvider = mock.NewTokenProvider(mockCtrl)

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var ctx = context.TODO()

	var component = NewComponent(targetRealm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, log.NewNopLogger())

	t.Run("Fails to store check in DB", func(t *testing.T) {
		var timestamp = int64(12345678)
		var check = api.CheckRepresentation{
			Operator: ptr("operator"),
			DateTime: &timestamp,
			Status:   ptr("status"),
		}
		var dbError = errors.New("db error")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(dbError)
		var err = component.CreateCheck(ctx, userID, check)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var timestamp = int64(12345678)
		var check = api.CheckRepresentation{
			Operator: ptr("operator"),
			DateTime: &timestamp,
			Status:   ptr("status"),
		}
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		var err = component.CreateCheck(ctx, userID, check)
		assert.Nil(t, err)
	})

}

func ptr(value string) *string {
	return &value
}
