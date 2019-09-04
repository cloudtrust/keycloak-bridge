package account

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func genericUpdatePasswordTest(t *testing.T, oldPasswd, newPasswd, confirmPassword string, kcCalls int, expectingError bool) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	var mockLogger = log.NewNopLogger()

	component := NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, confirmPassword).Return("", nil).Times(kcCalls)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(kcCalls)

	err := component.UpdatePassword(ctx, oldPasswd, newPasswd, confirmPassword)

	assert.Equal(t, expectingError, err != nil)
}

func TestUpdatePasswordNoChange(t *testing.T) {
	passwd := "a p@55w0rd"
	genericUpdatePasswordTest(t, passwd, passwd, passwd, 0, true)
}

func TestUpdatePasswordBadConfirm(t *testing.T) {
	oldPasswd := "prev10u5"
	newPasswd := "a p@55w0rd"
	genericUpdatePasswordTest(t, oldPasswd, newPasswd, newPasswd+newPasswd, 0, true)
}

func TestUpdatePassword(t *testing.T) {
	oldPasswd := "prev10u5"
	newPasswd := "a p@55w0rd"
	genericUpdatePasswordTest(t, oldPasswd, newPasswd, newPasswd, 1, false)
}

func TestUpdatePasswordWrongPwd(t *testing.T) {
	oldPasswd := "wrong prev10u5"
	newPasswd := "a p@55w0rd"

	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	var mockLogger = log.NewNopLogger()
	component := NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalidPasswordExistingMessage")).Times(1)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	err := component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd)

	assert.True(t, err != nil)

	mockKeycloakClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", fmt.Errorf("invalid")).Times(1)
	mockEventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	err = component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd)

	assert.True(t, err != nil)

}

func TestUpdateAccount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var accountComponent = NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

	accessToken := "access token"
	realmName := "master"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	var id = "1234-7454-4516"
	//var username = "username"
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
	var locale = "de"
	var createdTimestamp = time.Now().UTC().Unix()

	var attributes = make(map[string][]string)
	attributes["phoneNumber"] = []string{phoneNumber}
	attributes["label"] = []string{label}
	attributes["gender"] = []string{gender}
	attributes["birthDate"] = []string{birthDate}
	attributes["phoneNumberVerified"] = []string{strconv.FormatBool(phoneNumberVerified)}
	attributes["locale"] = []string{locale}

	var kcUserRep = kc.UserRepresentation{
		Id:               &id,
		Username:         &username,
		Email:            &email,
		Enabled:          &enabled,
		EmailVerified:    &emailVerified,
		FirstName:        &firstName,
		LastName:         &lastName,
		Attributes:       &attributes,
		CreatedTimestamp: &createdTimestamp,
	}

	var userRep = api.AccountRepresentation{
		Username:    &username,
		Email:       &email,
		FirstName:   &firstName,
		LastName:    &lastName,
		PhoneNumber: &phoneNumber,
	}

	// Update account with succces
	{
		mockEventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)

		mockKeycloakClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, phoneNumber, (*kcUserRep.Attributes)["phoneNumber"][0])
				return nil
			}).Times(1)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
	}

	// update by changing the email address
	{
		var oldEmail = "toti@elca.ch"
		var oldkcUserRep = kc.UserRepresentation{
			Id:            &id,
			Email:         &oldEmail,
			EmailVerified: &emailVerified,
		}
		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep, nil).Times(1)
		mockKeycloakClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, false, *kcUserRep.EmailVerified)
				return nil
			}).Times(1)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
	}

	var oldNumber = "+41789467"
	var oldAttributes = make(map[string][]string)
	oldAttributes["phoneNumber"] = []string{oldNumber}
	oldAttributes["phoneNumberVerified"] = []string{strconv.FormatBool(phoneNumberVerified)}
	var oldkcUserRep2 = kc.UserRepresentation{
		Id:         &id,
		Attributes: &oldAttributes,
	}

	// update by changing the phone number
	{

		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil).Times(1)
		mockKeycloakClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := strconv.ParseBool(((*kcUserRep.Attributes)["phoneNumberVerified"][0]))
				assert.Equal(t, phoneNumber, (*kcUserRep.Attributes)["phoneNumber"][0])
				assert.Equal(t, false, verified)
				return nil
			}).Times(1)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
	}

	// update without attributes
	{
		var userRepWithoutAttr = api.AccountRepresentation{
			Username:  &username,
			Email:     &email,
			FirstName: &firstName,
			LastName:  &lastName,
		}

		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil).Times(1)
		mockKeycloakClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := strconv.ParseBool(((*kcUserRep.Attributes)["phoneNumberVerified"][0]))
				assert.Equal(t, oldNumber, (*kcUserRep.Attributes)["phoneNumber"][0])
				assert.Equal(t, true, verified)
				return nil
			}).Times(1)

		err := accountComponent.UpdateAccount(ctx, userRepWithoutAttr)

		assert.Nil(t, err)
	}

	//Error - get user
	{
		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)

		err := accountComponent.UpdateAccount(ctx, api.AccountRepresentation{})

		assert.NotNil(t, err)
	}
	//Error - update user
	{
		var id = "1234-79894-7594"
		var kcUserRep = kc.UserRepresentation{
			Id: &id,
		}
		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).AnyTimes()
		mockKeycloakClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).Return(fmt.Errorf("Unexpected error")).Times(1)

		err := accountComponent.UpdateAccount(ctx, api.AccountRepresentation{})

		assert.NotNil(t, err)
	}
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	mockKeycloakClient := mock.NewAccKeycloakClient(mockCtrl)
	mockEventDBModule := mock.NewEventsDBModule(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var accountComponent = NewComponent(mockKeycloakClient, mockEventDBModule, mockLogger)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	// Get user with succces
	{
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
		var createdTimestamp = time.Now().UTC().Unix()
		var locale = "it"

		var attributes = make(map[string][]string)
		attributes["phoneNumber"] = []string{phoneNumber}
		attributes["label"] = []string{label}
		attributes["gender"] = []string{gender}
		attributes["birthDate"] = []string{birthDate}
		attributes["phoneNumberVerified"] = []string{strconv.FormatBool(phoneNumberVerified)}
		attributes["locale"] = []string{locale}

		var kcUserRep = kc.UserRepresentation{
			Id:               &id,
			Username:         &username,
			Email:            &email,
			Enabled:          &enabled,
			EmailVerified:    &emailVerified,
			FirstName:        &firstName,
			LastName:         &lastName,
			Attributes:       &attributes,
			CreatedTimestamp: &createdTimestamp,
		}

		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).Times(1)

		mockEventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		apiUserRep, err := accountComponent.GetAccount(ctx)

		assert.Nil(t, err)
		assert.Equal(t, username, *apiUserRep.Username)
		assert.Equal(t, email, *apiUserRep.Email)
		assert.Equal(t, firstName, *apiUserRep.FirstName)
		assert.Equal(t, lastName, *apiUserRep.LastName)
		assert.Equal(t, phoneNumber, *apiUserRep.PhoneNumber)
	}

	//Error
	{
		mockKeycloakClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error")).Times(1)
		_, err := accountComponent.GetAccount(ctx)

		assert.NotNil(t, err)
	}
}
