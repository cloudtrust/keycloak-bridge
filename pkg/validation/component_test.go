package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	log "github.com/cloudtrust/common-service/log"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
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
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)

	var accessToken = "abcd-1234"
	var realm = "my-realm"
	var userID = ""

	var ctx = context.Background()

	var component = NewComponent(realm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

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

	t.Run("Date parsing error", func(t *testing.T) {
		var expirationDate = "01.01-2020"
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDB.EXPECT().GetUser(ctx, realm, userID).Return(&dto.DBUser{
			IDDocumentExpiration: &expirationDate,
		}, nil)
		var _, err = component.GetUser(ctx, userID)
		assert.NotNil(t, err)
	})

	t.Run("Happy path", func(t *testing.T) {
		var expirationDate = "01.01.2020"
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mockKeycloakClient.EXPECT().GetUser(accessToken, realm, userID).Return(kc.UserRepresentation{}, nil)
		mockUsersDB.EXPECT().GetUser(ctx, realm, userID).Return(&dto.DBUser{
			IDDocumentExpiration: &expirationDate,
		}, nil)
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
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var accessToken = "abcdef"
	var ctx = context.TODO()

	var component = NewComponent(targetRealm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	t.Run("Fails to retrieve token for technical user", func(t *testing.T) {
		var user = api.UserRepresentation{
			FirstName: ptr("newFirstname"),
		}
		var kcError = errors.New("kc error")
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return("", kcError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("No update needed", func(t *testing.T) {
		var user = api.UserRepresentation{}
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
		var date = time.Now()
		var user = api.UserRepresentation{
			BirthDate: &date,
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).Times(2)
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
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).Times(2)
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
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).Times(2)
		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, userID).Return(kc.UserRepresentation{}, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, gomock.Any()).Return(nil)
		var dbError = errors.New("db error")
		mockUsersDB.EXPECT().StoreOrUpdateUser(ctx, targetRealm, gomock.Any()).Return(dbError)
		var err = component.UpdateUser(ctx, userID, user)
		assert.NotNil(t, err)
	})

	t.Run("Failure to store event", func(t *testing.T) {
		var date = time.Now()
		var user = api.UserRepresentation{
			FirstName:            ptr("newFirstname"),
			IDDocumentExpiration: &date,
		}
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).Times(2)
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
		mockTokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil).Times(2)
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
	var mockAccreditations = mock.NewAccreditationsModule(mockCtrl)

	var targetRealm = "cloudtrust"
	var userID = "abc789def"
	var accessToken = "the-access-token"
	var ctx = context.TODO()
	var datetime = time.Now()
	var check = api.CheckRepresentation{
		Operator: ptr("operator"),
		DateTime: &datetime,
		Status:   ptr("status"),
	}

	var component = NewComponent(targetRealm, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockEventsDB, mockAccreditations, log.NewNopLogger())

	t.Run("Fails to store check in DB", func(t *testing.T) {
		var dbError = errors.New("db error")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(dbError)
		var err = component.CreateCheck(ctx, userID, check)
		assert.NotNil(t, err)
	})

	t.Run("Can't get access token", func(t *testing.T) {
		check.Status = ptr("SUCCESS")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", errors.New("no token"))
		var err = component.CreateCheck(ctx, userID, check)
		assert.NotNil(t, err)
	})
	t.Run("Accreditation module fails", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 0, errors.New("Accreds failed"))
		var err = component.CreateCheck(ctx, userID, check)
		assert.NotNil(t, err)
	})

	t.Run("Success w/o accreditations", func(t *testing.T) {
		check.Status = ptr("FRAUD_SUSPICION_CONFIRMED")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockEventsDB.EXPECT().ReportEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
			gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		var err = component.CreateCheck(ctx, userID, check)
		assert.Nil(t, err)
	})
	t.Run("Computed accreditations, fails to store them in Keycloak", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 1, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, kcUser).Return(errors.New("KC fails"))
		var err = component.CreateCheck(ctx, userID, check)
		assert.NotNil(t, err)
	})
	t.Run("Success with accreditations", func(t *testing.T) {
		var kcUser kc.UserRepresentation
		check.Status = ptr("SUCCESS")
		mockUsersDB.EXPECT().CreateCheck(ctx, targetRealm, userID, gomock.Any()).Return(nil)
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mockAccreditations.EXPECT().GetUserAndPrepareAccreditations(ctx, accessToken, targetRealm, userID, keycloakb.CredsIDNow).Return(kcUser, 1, nil)
		mockKeycloakClient.EXPECT().UpdateUser(accessToken, targetRealm, userID, kcUser).Return(nil)
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
