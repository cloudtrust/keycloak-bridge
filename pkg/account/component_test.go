package account

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/log"
	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

func TestUpdatePassword(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()
	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Update password: no change", func(t *testing.T) {
		oldPasswd := "a p@55w0rd"
		err := component.UpdatePassword(ctx, oldPasswd, oldPasswd, oldPasswd)

		assert.NotNil(t, err)
	})

	t.Run("Update password: bad confirm", func(t *testing.T) {
		oldPasswd := "prev10u5"
		newPasswd := "a p@55w0rd"
		confirmPasswd := "bad one"
		err := component.UpdatePassword(ctx, oldPasswd, newPasswd, confirmPasswd)

		assert.NotNil(t, err)
	})

	t.Run("Update password: success", func(t *testing.T) {
		oldPasswd := "prev10u5"
		newPasswd := "a p@55w0rd"
		confirmPasswd := "a p@55w0rd"
		mockKeycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, confirmPasswd).Return("", nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
		mockKeycloakAccountClient.EXPECT().SendEmail(accessToken, realm, emailTemplateUpdatedPassword, emailSubjectUpdatedPassword, nil, gomock.Any()).Return(nil)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "UPDATED_PWD_EMAIL_SENT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := component.UpdatePassword(ctx, oldPasswd, newPasswd, confirmPasswd)

		assert.Nil(t, err)
	})
}

func TestUpdatePasswordWrongPwd(t *testing.T) {
	oldPasswd := "wrong prev10u5"
	newPasswd := "a p@55w0rd"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, log.NewNopLogger())

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Error test case 1", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalidPasswordExistingMessage")).Times(1)

		assert.NotNil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})

	t.Run("Error test case 2", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalid")).Times(1)

		assert.NotNil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})

	t.Run("Password reset succeeded but storing the event failed", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username).Return(errors.New("error")).Times(1)
		mockKeycloakAccountClient.EXPECT().SendEmail(accessToken, realm, emailTemplateUpdatedPassword, emailSubjectUpdatedPassword, nil, gomock.Any()).Return(errors.New(""))

		assert.Nil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})
}

func TestUpdateAccount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	var accountComponent = NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	accessToken := "access token"
	realmName := "master"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	var id = "1234-7454-4516"
	var email = "toto@elca.ch"
	var enabled = true
	var emailVerified = true
	var firstName = "Titi"
	var lastName = "Tutu"
	var phoneNumber = "+41789456"
	var phoneNumberVerified = true
	var label = "Label"
	var gender = "M"
	var birthDate = "01/01/1988"
	var birthLocation = "Antananarivo"
	var nationality = "FR"
	var locale = "de"
	var idDocType = "PASSPORT"
	var idDocNumber = "ABC123-DEF456"
	var idDocExpiration = "01.01.2050"
	var idDocCountry = "CH"
	var createdTimestamp = time.Now().UTC().Unix()
	var anError = errors.New("any error")

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, locale)

	var kcUserRep = kc.UserRepresentation{
		ID:               &id,
		Username:         &username,
		Email:            &email,
		Enabled:          &enabled,
		EmailVerified:    &emailVerified,
		FirstName:        &firstName,
		LastName:         &lastName,
		Attributes:       &attributes,
		CreatedTimestamp: &createdTimestamp,
	}
	var dbUser = dto.DBUser{
		UserID:               &userID,
		BirthLocation:        &birthLocation,
		Nationality:          &nationality,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
		IDDocumentCountry:    &idDocCountry,
	}

	var userRep = api.AccountRepresentation{
		Username:    &username,
		Email:       &email,
		FirstName:   &firstName,
		LastName:    &lastName,
		Gender:      &gender,
		PhoneNumber: &phoneNumber,
		BirthDate:   &birthDate,
		Locale:      &locale,
	}

	t.Run("GetAccount fails", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, anError)

		var err = accountComponent.UpdateAccount(ctx, userRep)

		assert.Equal(t, anError, err)
	})

	t.Run("Update account with succces", func(t *testing.T) {
		mockEventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				return nil
			}).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dbUser, nil)
		mockUsersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
	})
	t.Run("Keycloak update succces - DB get user fails", func(t *testing.T) {
		mockEventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{}, errors.New("db error"))

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.NotNil(t, err)
	})
	t.Run("Keycloak update succces - DB update fails", func(t *testing.T) {
		mockEventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).Return(nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockUsersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(errors.New("db error"))

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.NotNil(t, err)
	})

	t.Run("Update by changing the email address", func(t *testing.T) {
		userRep.PhoneNumber = nil
		var oldEmail = "toti@elca.ch"
		var oldkcUserRep = kc.UserRepresentation{
			ID:            &id,
			Email:         &oldEmail,
			EmailVerified: &emailVerified,
		}
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep, nil).Times(1)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, false, *kcUserRep.EmailVerified)
				return nil
			}).Times(1)
		mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyEmail}).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventAdditionalInfo, gomock.Any()).Return(nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockUsersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(nil)
		// Mail updated
		mockKeycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedEmail, emailSubjectUpdatedEmail, &oldEmail, gomock.Any()).Return(nil)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "EMAIL_CHANGED_EMAIL_SENT", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventUsername, username).Return(nil)
		// Profile updated
		mockKeycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, gomock.Any()).Return(nil)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "PROFILE_CHANGED_EMAIL_SENT", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventUsername, username).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
		userRep.PhoneNumber = &phoneNumber
	})

	// Profile update
	mockKeycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, gomock.Any()).Return(anError).AnyTimes()

	var oldNumber = "+41789467"
	var oldAttributes = make(kc.Attributes)
	oldAttributes[constants.AttrbPhoneNumber] = []string{oldNumber}
	oldAttributes[constants.AttrbPhoneNumberVerified] = []string{strconv.FormatBool(phoneNumberVerified)}
	var oldkcUserRep2 = kc.UserRepresentation{
		ID:         &id,
		Email:      &email,
		Attributes: &oldAttributes,
	}

	t.Run("Update by changing the phone number", func(t *testing.T) {
		userRep.Email = nil
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil).Times(1)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, false, *verified)
				return nil
			}).Times(1)
		mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyPhoneNumber}).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventAdditionalInfo, gomock.Any()).Return(nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockUsersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
		userRep.Email = &email
	})

	t.Run("Update by changing the phone number-Execute actions email fails", func(t *testing.T) {
		var anError = errors.New("any error")
		userRep.Email = nil
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, false, *verified)
				return nil
			})
		mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyPhoneNumber}).Return(anError)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Equal(t, anError, err)
	})

	t.Run("Update without attributes", func(t *testing.T) {
		var userRepWithoutAttr = api.AccountRepresentation{
			Username:  &username,
			Email:     &email,
			FirstName: &firstName,
			LastName:  &lastName,
		}

		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil).Times(1)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, oldNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, true, *verified)
				return nil
			}).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockUsersDetailsDBModule.EXPECT().StoreOrUpdateUserDetails(ctx, realmName, gomock.Any()).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRepWithoutAttr)

		assert.Nil(t, err)
	})

	t.Run("Error - get user", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		err := accountComponent.UpdateAccount(ctx, api.AccountRepresentation{})

		assert.NotNil(t, err)
	})
	t.Run("Error - update user", func(t *testing.T) {
		var id = "1234-79894-7594"
		var kcUserRep = kc.UserRepresentation{
			ID: &id,
		}
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).AnyTimes()
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockKeycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).Return(fmt.Errorf("Unexpected error")).Times(1)

		err := accountComponent.UpdateAccount(ctx, api.AccountRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	var accountComponent = NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"
	var userID = "1234-7454-4516"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Call to Keycloak fails", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))
		_, err := accountComponent.GetAccount(ctx)

		assert.NotNil(t, err)
	})

	t.Run("Call to database fails", func(t *testing.T) {
		var dbError = errors.New("db error")
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, nil)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{}, dbError)
		_, err := accountComponent.GetAccount(ctx)

		assert.Equal(t, dbError, err)
	})

	var email = "toto@elca.ch"
	var enabled = true
	var emailVerified = true
	var firstName = "Titi"
	var lastName = "Tutu"
	var phoneNumber = "+41789456"
	var phoneNumberVerified = true
	var label = "Label"
	var gender = "M"
	var birthDate = "01/01/1988"
	var createdTimestamp = time.Now().UTC().Unix()
	var locale = "it"

	var attributes = make(kc.Attributes)
	attributes[constants.AttrbPhoneNumber] = []string{phoneNumber}
	attributes[constants.AttrbLabel] = []string{label}
	attributes[constants.AttrbGender] = []string{gender}
	attributes[constants.AttrbBirthDate] = []string{birthDate}
	attributes[constants.AttrbPhoneNumberVerified] = []string{strconv.FormatBool(phoneNumberVerified)}
	attributes[constants.AttrbLocale] = []string{locale}

	var kcUserRep = kc.UserRepresentation{
		Username:         &username,
		Email:            &email,
		Enabled:          &enabled,
		EmailVerified:    &emailVerified,
		FirstName:        &firstName,
		LastName:         &lastName,
		Attributes:       &attributes,
		CreatedTimestamp: &createdTimestamp,
	}

	t.Run("Get user with succces", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			UserID: &userID,
		}, nil)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		apiUserRep, err := accountComponent.GetAccount(ctx)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
		assert.Nil(t, apiUserRep.BirthLocation)
		assert.Nil(t, apiUserRep.Nationality)
		assert.Nil(t, apiUserRep.IDDocumentType)
		assert.Nil(t, apiUserRep.IDDocumentNumber)
		assert.Nil(t, apiUserRep.IDDocumentExpiration)
		assert.Nil(t, apiUserRep.IDDocumentCountry)
	})

	t.Run("Get user with succces", func(t *testing.T) {
		var birthLocation = "Luzern"
		var nationality = "CH"
		var docType = "PASSPORT"
		var docID = "PASS123456789"
		var docExp = "31.12.2029"
		var docCountry = "CH"
		mockKeycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)
		mockUsersDetailsDBModule.EXPECT().GetUserDetails(ctx, realmName, userID).Return(dto.DBUser{
			BirthLocation:        &birthLocation,
			Nationality:          &nationality,
			IDDocumentType:       &docType,
			IDDocumentNumber:     &docID,
			IDDocumentExpiration: &docExp,
			IDDocumentCountry:    &docCountry,
		}, nil)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		apiUserRep, err := accountComponent.GetAccount(ctx)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, gender, *apiUserRep.Gender)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
		assert.Equal(t, birthDate, *apiUserRep.BirthDate)
		assert.Equal(t, birthLocation, *apiUserRep.BirthLocation)
		assert.Equal(t, nationality, *apiUserRep.Nationality)
		assert.Equal(t, docType, *apiUserRep.IDDocumentType)
		assert.Equal(t, docID, *apiUserRep.IDDocumentNumber)
		assert.Equal(t, docExp, *apiUserRep.IDDocumentExpiration)
		assert.Equal(t, docCountry, *apiUserRep.IDDocumentCountry)
	})
}

func TestDeleteUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	var accountComponent = NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Delete user with succces", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().DeleteAccount(accessToken, realmName).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(ctx, "SELF_DELETE_ACCOUNT", "self-service", gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := accountComponent.DeleteAccount(ctx)

		assert.Nil(t, err)
	})

	t.Run("Delete user fails", func(t *testing.T) {
		mockKeycloakAccountClient.EXPECT().DeleteAccount(accessToken, realmName).Return(fmt.Errorf("Unexpected error")).Times(1)
		err := accountComponent.DeleteAccount(ctx)

		assert.NotNil(t, err)
	})
}

func TestGetCredentials(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var currentRealm = "master"
	var currentUserID = "1234-789"

	// Get credentials with succces
	{
		var id = "1245"

		var kcCredRep = kc.CredentialRepresentation{
			ID: &id,
		}

		var kcCredsRep []kc.CredentialRepresentation
		kcCredsRep = append(kcCredsRep, kcCredRep)

		mockKeycloakAccountClient.EXPECT().GetCredentials(accessToken, currentRealm).Return(kcCredsRep, nil).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		apiCredsRep, err := component.GetCredentials(ctx)

		var expectedAPICredRep = account_api.CredentialRepresentation{
			ID: &id,
		}

		var expectedAPICredsRep []account_api.CredentialRepresentation
		expectedAPICredsRep = append(expectedAPICredsRep, expectedAPICredRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPICredsRep, apiCredsRep)
	}

	//Error
	{
		mockKeycloakAccountClient.EXPECT().GetCredentials(accessToken, currentRealm).Return([]kc.CredentialRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		_, err := component.GetCredentials(ctx)

		assert.NotNil(t, err)
	}
}

func TestGetCredentialRegistrators(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var currentRealm = "master"
	var currentUserID = "1234-789"

	// Get credential types with succces
	{
		var credTypes = []string{"paper", "push"}

		mockKeycloakAccountClient.EXPECT().GetCredentialRegistrators(accessToken, currentRealm).Return(credTypes, nil).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		resCredTypes, err := component.GetCredentialRegistrators(ctx)

		assert.Nil(t, err)
		assert.Equal(t, credTypes, resCredTypes)
	}

	//Error
	{
		mockKeycloakAccountClient.EXPECT().GetCredentialRegistrators(accessToken, currentRealm).Return([]string{}, fmt.Errorf("Unexpected error")).Times(1)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		_, err := component.GetCredentialRegistrators(ctx)

		assert.NotNil(t, err)
	}
}

func TestUpdateLabelCredential(t *testing.T) {

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	credentialID := "78945-845"
	label := "cred label"

	{
		mockKeycloakAccountClient.EXPECT().UpdateLabelCredential(accessToken, realm, credentialID, label).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_UPDATE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		err := component.UpdateLabelCredential(ctx, credentialID, label)

		assert.Nil(t, err)
	}

	{
		mockKeycloakAccountClient.EXPECT().UpdateLabelCredential(accessToken, realm, credentialID, label).Return(fmt.Errorf("Unexpected error")).Times(1)
		err := component.UpdateLabelCredential(ctx, credentialID, label)

		assert.NotNil(t, err)
	}
}

func TestDeleteCredential(t *testing.T) {

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	credentialID := "78945-845"
	{
		mockKeycloakAccountClient.EXPECT().DeleteCredential(accessToken, realm, credentialID).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_DELETE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		err := component.DeleteCredential(ctx, credentialID)

		assert.Nil(t, err)
	}

	{
		mockKeycloakAccountClient.EXPECT().DeleteCredential(accessToken, realm, credentialID).Return(fmt.Errorf("Unexpected error")).Times(1)
		err := component.DeleteCredential(ctx, credentialID)

		assert.NotNil(t, err)
	}
}

func TestMoveCredential(t *testing.T) {

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	credentialID := "78945-845"
	previousCredentialID := "6589-7841"
	{
		mockKeycloakAccountClient.EXPECT().MoveAfter(accessToken, realm, credentialID, previousCredentialID).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_MOVE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		err := component.MoveCredential(ctx, credentialID, previousCredentialID)

		assert.Nil(t, err)
	}

	{
		mockKeycloakAccountClient.EXPECT().MoveToFirst(accessToken, realm, credentialID).Return(nil).Times(1)
		mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_MOVE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

		err := component.MoveCredential(ctx, credentialID, "null")

		assert.Nil(t, err)
	}

	{
		mockKeycloakAccountClient.EXPECT().MoveAfter(accessToken, realm, credentialID, previousCredentialID).Return(fmt.Errorf("Unexpected error")).Times(1)
		err := component.MoveCredential(ctx, credentialID, previousCredentialID)

		assert.NotNil(t, err)
	}

	{
		mockKeycloakAccountClient.EXPECT().MoveToFirst(accessToken, realm, credentialID).Return(fmt.Errorf("Unexpected error")).Times(1)
		err := component.MoveCredential(ctx, credentialID, "null")

		assert.NotNil(t, err)
	}

}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakAccountClient := mock.NewKeycloakAccountClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	mockConfigurationDBModule := mock.NewConfigurationDBModule(mockCtrl)
	mockUsersDetailsDBModule := mock.NewUsersDetailsDBModule(mockCtrl)
	mockLogger := log.NewNopLogger()

	component := NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var currentRealm = "master"
	var currentUserID = "1234-789"
	var falseBool = false
	var trueBool = true
	var config = configuration.RealmConfiguration{
		APISelfAuthenticatorDeletionEnabled: &falseBool,
		APISelfAccountEditingEnabled:        &falseBool,
		APISelfAccountDeletionEnabled:       &falseBool,
		APISelfPasswordChangeEnabled:        &falseBool,
		DefaultClientID:                     new(string),
		DefaultRedirectURI:                  new(string),
		ShowAuthenticatorsTab:               &trueBool,
		ShowAccountDeletionButton:           &trueBool,
		ShowPasswordTab:                     &trueBool,
		ShowProfileTab:                      &trueBool,
	}
	var adminConfig configuration.RealmAdminConfiguration

	t.Run("Get configuration with succces", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		mockConfigurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(config, nil).Times(1)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(adminConfig, nil).Times(1)

		resConfig, err := component.GetConfiguration(ctx, "")

		assert.Nil(t, err)
		assert.Equal(t, *config.ShowAuthenticatorsTab, *resConfig.ShowAuthenticatorsTab)
		assert.Equal(t, *config.ShowAccountDeletionButton, *resConfig.ShowAccountDeletionButton)
		assert.Equal(t, *config.ShowPasswordTab, *resConfig.ShowPasswordTab)
		assert.Equal(t, *config.ShowProfileTab, *resConfig.ShowProfileTab)
	})

	t.Run("Get configuration with override realm with succces", func(t *testing.T) {
		var overrideRealm = "customerRealm"
		var successURL = "https://success.io"

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		mockConfigurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(config, nil).Times(1)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(adminConfig, nil).Times(1)
		mockConfigurationDBModule.EXPECT().GetConfiguration(ctx, overrideRealm).Return(configuration.RealmConfiguration{
			RedirectSuccessfulRegistrationURL: &successURL,
		}, nil).Times(1)

		resConfig, err := component.GetConfiguration(ctx, overrideRealm)

		assert.Nil(t, err)
		assert.Equal(t, *config.ShowAuthenticatorsTab, *resConfig.ShowAuthenticatorsTab)
		assert.Equal(t, *config.ShowAccountDeletionButton, *resConfig.ShowAccountDeletionButton)
		assert.Equal(t, *config.ShowProfileTab, *resConfig.ShowProfileTab)
		assert.Equal(t, *config.ShowPasswordTab, *resConfig.ShowPasswordTab)
		assert.Equal(t, successURL, *resConfig.RedirectSuccessfulRegistrationURL)
	})

	t.Run("Error on GetConfiguration", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		mockConfigurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(configuration.RealmConfiguration{}, fmt.Errorf("Unexpected error")).Times(1)

		_, err := component.GetConfiguration(ctx, "")

		assert.NotNil(t, err)
	})
	t.Run("Error on GetAdminConfiguration", func(t *testing.T) {
		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		mockConfigurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(configuration.RealmConfiguration{}, nil).Times(1)
		mockConfigurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(configuration.RealmAdminConfiguration{}, fmt.Errorf("Unexpected error")).Times(1)

		_, err := component.GetConfiguration(ctx, "")

		assert.NotNil(t, err)
	})
}

func TestSendVerify(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockKeycloakAccountClient = mock.NewKeycloakAccountClient(mockCtrl)
		mockEventDBModule         = mock.NewEventsDBModule(mockCtrl)
		mockConfigurationDBModule = mock.NewConfigurationDBModule(mockCtrl)
		mockUsersDetailsDBModule  = mock.NewUsersDetailsDBModule(mockCtrl)
		mockLogger                = log.NewNopLogger()

		component     = NewComponent(mockKeycloakAccountClient, mockEventDBModule, mockConfigurationDBModule, mockUsersDetailsDBModule, mockLogger)
		accessToken   = "TOKEN=="
		currentRealm  = "master"
		currentUserID = "1234-789"
		ctx           = context.TODO()
	)

	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

	// SendVerifyEmail
	t.Run("SendVerifyEmail - fails", func(t *testing.T) {
		var expected = errors.New("kc fails")
		mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyEmail}).Return(expected)
		var err = component.SendVerifyEmail(ctx)
		assert.Equal(t, expected, err)
	})
	t.Run("SendVerifyEmail - success", func(t *testing.T) {
		gomock.InOrder(
			mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyEmail}).Return(nil),
			mockEventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, currentRealm,
				database.CtEventUserID, currentUserID, database.CtEventAdditionalInfo, gomock.Any()),
		)
		assert.Nil(t, component.SendVerifyEmail(ctx))
	})

	// SendVerifyPhoneNumber
	t.Run("SendVerifyPhoneNumber - fails", func(t *testing.T) {
		var expected = errors.New("kc fails")
		gomock.InOrder(
			mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyPhoneNumber}).Return(expected),
		)
		var err = component.SendVerifyPhoneNumber(ctx)
		assert.Equal(t, expected, err)
	})
	t.Run("SendVerifyPhoneNumber - success", func(t *testing.T) {
		gomock.InOrder(
			mockKeycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyPhoneNumber}).Return(nil),
			mockEventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, currentRealm,
				database.CtEventUserID, currentUserID, database.CtEventAdditionalInfo, gomock.Any()),
		)
		assert.Nil(t, component.SendVerifyPhoneNumber(ctx))
	})
}
