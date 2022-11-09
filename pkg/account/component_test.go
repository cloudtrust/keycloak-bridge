package account

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/log"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/pkg/account/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"
)

type componentMock struct {
	keycloakAccountClient   *mock.KeycloakAccountClient
	keycloakTechnicalClient *mock.KeycloakTechnicalClient
	eventDBModule           *mock.EventsDBModule
	configurationDBModule   *mock.ConfigurationDBModule
	glnVerifier             *mock.GlnVerifier
	accreditationsClient    *mock.AccreditationsServiceClient
}

func createComponentMocks(mockCtrl *gomock.Controller) *componentMock {
	return &componentMock{
		keycloakAccountClient:   mock.NewKeycloakAccountClient(mockCtrl),
		keycloakTechnicalClient: mock.NewKeycloakTechnicalClient(mockCtrl),
		eventDBModule:           mock.NewEventsDBModule(mockCtrl),
		configurationDBModule:   mock.NewConfigurationDBModule(mockCtrl),
		glnVerifier:             mock.NewGlnVerifier(mockCtrl),
		accreditationsClient:    mock.NewAccreditationsServiceClient(mockCtrl),
	}
}

func (m *componentMock) createComponent() *component {
	return NewComponent(m.keycloakAccountClient, m.keycloakTechnicalClient, m.eventDBModule,
		m.configurationDBModule, m.glnVerifier, m.accreditationsClient, log.NewNopLogger()).(*component)
}

func ptr(value string) *string {
	return &value
}

func TestUpdatePassword(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

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
		anyError := errors.New("any error")
		oldPasswd := "prev10u5"
		newPasswd := "a p@55w0rd"
		confirmPasswd := "a p@55w0rd"
		mocks.keycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, confirmPasswd).Return("", nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realm, emailTemplateUpdatedPassword, emailSubjectUpdatedPassword, nil, gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "UPDATED_PWD_EMAIL_SENT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		mocks.keycloakTechnicalClient.EXPECT().LogoutAllSessions(gomock.Any(), realm, userID).Return(anyError)

		err := component.UpdatePassword(ctx, oldPasswd, newPasswd, confirmPasswd)

		assert.Nil(t, err)
	})
}

func TestUpdatePasswordWrongPwd(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	oldPasswd := "wrong prev10u5"
	newPasswd := "a p@55w0rd"
	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Error test case 1", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", errors.New("invalidPasswordExistingMessage"))

		assert.NotNil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})

	t.Run("Error test case 2", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", errors.New("invalid"))

		assert.NotNil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})

	t.Run("Password reset succeeded but storing the event failed", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().UpdatePassword(accessToken, realm, oldPasswd, newPasswd, newPasswd).Return("", nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "PASSWORD_RESET", "self-service", database.CtEventRealmName, realm, database.CtEventUserID, userID, database.CtEventUsername, username).Return(errors.New("error"))
		mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realm, emailTemplateUpdatedPassword, emailSubjectUpdatedPassword, nil, gomock.Any()).Return(errors.New(""))
		mocks.keycloakTechnicalClient.EXPECT().LogoutAllSessions(gomock.Any(), realm, userID)

		assert.Nil(t, component.UpdatePassword(ctx, oldPasswd, newPasswd, newPasswd))
	})
}

func TestUpdateAccount(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var accountComponent = mocks.createComponent()

	var (
		accessToken         = "access token"
		realmName           = "master"
		userID              = "123-456-789"
		username            = "username"
		id                  = userID
		email               = "toto@elca.ch"
		enabled             = true
		emailVerified       = true
		firstName           = "Titi"
		lastName            = "Tutu"
		phoneNumber         = "+41789456"
		phoneNumberVerified = true
		label               = "Label"
		gender              = "M"
		birthDate           = "01/01/1988"
		birthLocation       = "Antananarivo"
		nationality         = "FR"
		locale              = "de"
		idDocType           = "PASSPORT"
		idDocNumber         = "ABC123-DEF456"
		idDocExpiration     = "01.01.2050"
		idDocCountry        = "CH"
		bFalse              = false
		createdTimestamp    = time.Now().UTC().Unix()
		anError             = errors.New("any error")
	)
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, locale)
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, &birthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, &nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, &idDocType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, &idDocNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, &idDocExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, &idDocCountry)

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
	var userRep = api.UpdatableAccountRepresentation{
		Username:    &username,
		Email:       &email,
		FirstName:   &firstName,
		LastName:    &lastName,
		Gender:      &gender,
		PhoneNumber: &phoneNumber,
		BirthDate:   &birthDate,
		Locale:      &locale,
	}
	var one = 1
	var searchedUsers = kc.UsersPageRepresentation{Count: &one, Users: []kc.UserRepresentation{kcUserRep}}

	t.Run("GetAccount fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, anError)

		var err = accountComponent.UpdateAccount(ctx, userRep)

		assert.Equal(t, anError, err)
	})

	t.Run("Call to accreditations service fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, anError)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Equal(t, anError, err)
	})
	mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(nil, nil).AnyTimes()

	t.Run("GetAdminConfiguration fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, anError)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.NotNil(t, err)
	})
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{ShowGlnEditing: &bFalse}, nil).AnyTimes()

	t.Run("Update account with succces", func(t *testing.T) {
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, lastName, *kcUserRep.LastName)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				return nil
			})

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
	})

	t.Run("Update by changing the email address", func(t *testing.T) {
		userRep.PhoneNumber = nil
		var oldEmail = "toti@elca.ch"
		var oldkcUserRep = kc.UserRepresentation{
			ID:            &id,
			Email:         &oldEmail,
			EmailVerified: &emailVerified,
		}
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				// Email has not been updated...
				assert.NotEqual(t, email, *kcUserRep.Email)
				// ... but it was added to emailToValidate
				assert.Equal(t, email, *kcUserRep.GetAttributeString(constants.AttrbEmailToValidate))
				return nil
			})
		mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyEmail}).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventAdditionalInfo, gomock.Any()).Return(nil)
		// Mail updated
		mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedEmail, emailSubjectUpdatedEmail, &oldEmail, gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "EMAIL_CHANGED_EMAIL_SENT", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventUsername, username).Return(nil)
		// Profile updated
		mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, gomock.Any()).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "PROFILE_CHANGED_EMAIL_SENT", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventUsername, username).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
		userRep.PhoneNumber = &phoneNumber
	})

	mocks.keycloakTechnicalClient.EXPECT().GetUsers(ctx, realmName, "email", "="+email).Return(searchedUsers, nil).AnyTimes()

	// Profile update
	mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, emailTemplateUpdatedProfile, emailSubjectUpdatedProfile, nil, gomock.Any()).Return(anError).AnyTimes()

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
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				// Phone number has not been updated...
				assert.NotEqual(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				// ... but phone number has been written in "to validate" attribute
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumberToValidate))
				return nil
			})
		mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyPhoneNumber}).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, realmName,
			database.CtEventUserID, userID, database.CtEventAdditionalInfo, gomock.Any()).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Nil(t, err)
		userRep.Email = &email
	})

	t.Run("Update by changing the phone number-Execute actions email fails", func(t *testing.T) {
		var anError = errors.New("any error")
		userRep.Email = nil
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				// Phone number has not been updated...
				assert.NotEqual(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				// ... but phone number has been written in "to validate" attribute
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumberToValidate))
				return nil
			})
		mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, []string{ActionVerifyPhoneNumber}).Return(anError)

		err := accountComponent.UpdateAccount(ctx, userRep)

		assert.Equal(t, anError, err)
	})

	t.Run("Update without attributes - remove businessID", func(t *testing.T) {
		var userRepWithoutAttr = api.UpdatableAccountRepresentation{
			Username:   &username,
			Email:      &email,
			FirstName:  &firstName,
			LastName:   &lastName,
			BusinessID: csjson.OptionalString{Defined: true, Value: nil},
		}

		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(oldkcUserRep2, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				verified, _ := kcUserRep.GetAttributeBool(constants.AttrbPhoneNumberVerified)
				assert.Equal(t, oldNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, true, *verified)
				assert.Nil(t, kcUserRep.GetAttributeString(constants.AttrbBusinessID))
				return nil
			})

		err := accountComponent.UpdateAccount(ctx, userRepWithoutAttr)

		assert.Nil(t, err)
	})

	t.Run("Error - get user", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, fmt.Errorf("Unexpected error"))

		err := accountComponent.UpdateAccount(ctx, api.UpdatableAccountRepresentation{})

		assert.NotNil(t, err)
	})
	t.Run("Error - update user", func(t *testing.T) {
		var id = "1234-79894-7594"
		var kcUserRep = kc.UserRepresentation{
			ID: &id,
		}
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil).AnyTimes()
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).Return(fmt.Errorf("Unexpected error"))

		err := accountComponent.UpdateAccount(ctx, api.UpdatableAccountRepresentation{})

		assert.NotNil(t, err)
	})
}

func TestUpdateAccountRevokeAccreditation(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var accountComponent = mocks.createComponent()

	var (
		accessToken         = "access token"
		realmName           = "master"
		userID              = "123-456-789"
		username            = "username"
		id                  = "1234-7454-4516"
		email               = "toto@elca.ch"
		enabled             = true
		emailVerified       = true
		firstName           = "Titi"
		lastName            = "Tutu"
		phoneNumber         = "+41789456"
		phoneNumberVerified = true
		label               = "Label"
		gender              = "M"
		birthDate           = "01/01/1988"
		birthLocation       = "Antananarivo"
		nationality         = "FR"
		locale              = "de"
		idDocType           = "PASSPORT"
		idDocNumber         = "ABC123-DEF456"
		idDocExpiration     = "01.01.2050"
		idDocCountry        = "CH"
		bFalse              = false
		createdTimestamp    = time.Now().UTC().Unix()
	)

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, locale)
	attributes.SetStringWhenNotNil(constants.AttrbBirthLocation, &birthLocation)
	attributes.SetStringWhenNotNil(constants.AttrbNationality, &nationality)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentType, &idDocType)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentNumber, &idDocNumber)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentExpiration, &idDocExpiration)
	attributes.SetStringWhenNotNil(constants.AttrbIDDocumentCountry, &idDocCountry)

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
	var accred = []string{`{"type":"ONE", "expiryDate":"01.01.2025"}`}
	var revokedTypes = []string{"ONE"}
	var revokedAccred = []string{`{"type":"ONE","expiryDate":"01.01.2025","revoked":true}`}
	kcUserRep.SetAttribute(constants.AttrbAccreditations, accred)

	t.Run("Update account with succces - revoke accreditation", func(t *testing.T) {
		var otherLastName = "Toto"
		var userRepUpdate = api.UpdatableAccountRepresentation{
			Username:    &username,
			Email:       &email,
			FirstName:   &firstName,
			LastName:    &otherLastName,
			Gender:      &gender,
			PhoneNumber: &phoneNumber,
			BirthDate:   &birthDate,
			Locale:      &locale,
		}

		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().NotifyUpdate(ctx, gomock.Any()).Return(revokedTypes, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{ShowGlnEditing: &bFalse}, nil)
		mocks.keycloakAccountClient.EXPECT().UpdateAccount(accessToken, realmName, gomock.Any()).DoAndReturn(
			func(accessToken, realmName string, kcUserRep kc.UserRepresentation) error {
				assert.Equal(t, username, *kcUserRep.Username)
				assert.Equal(t, email, *kcUserRep.Email)
				assert.Equal(t, firstName, *kcUserRep.FirstName)
				assert.Equal(t, otherLastName, *kcUserRep.LastName)
				assert.Equal(t, phoneNumber, *kcUserRep.GetAttributeString(constants.AttrbPhoneNumber))
				assert.Equal(t, revokedAccred, kcUserRep.GetAttribute(constants.AttrbAccreditations))
				return nil
			})
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "UPDATE_ACCOUNT", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
		mocks.keycloakAccountClient.EXPECT().SendEmail(accessToken, realmName, gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "PROFILE_CHANGED_EMAIL_SENT", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		err := accountComponent.UpdateAccount(ctx, userRepUpdate)
		assert.Nil(t, err)
	})
}

func TestCheckGLN(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var accountComponent = mocks.createComponent()

	var realmName = "my-realm"
	var gln = "123456789"
	var firstName = "first"
	var lastName = "last"
	var newGLN = csjson.OptionalString{Defined: true, Value: &gln}
	var removeGLN = csjson.OptionalString{Defined: true, Value: nil}
	var noGLNChange = csjson.OptionalString{Defined: false}
	var kcUser = kc.UserRepresentation{FirstName: &firstName, LastName: &lastName}
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.TODO(), cs.CtContextRealm, realmName)

	t.Run("GetRealmAdminConfiguration fails", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, anyError)

		var err = accountComponent.checkGLN(ctx, newGLN, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("GLN feature not activated", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(configuration.RealmAdminConfiguration{}, nil)

		var err = accountComponent.checkGLN(ctx, newGLN, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})

	var bTrue = true
	var confWithGLN = configuration.RealmAdminConfiguration{ShowGlnEditing: &bTrue}
	mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, realmName).Return(confWithGLN, nil).AnyTimes()

	t.Run("Removing GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		var err = accountComponent.checkGLN(ctx, removeGLN, &kcUser)
		assert.Nil(t, err)
		assert.Nil(t, kcUser.GetAttributeString(constants.AttrbBusinessID))
	})
	t.Run("Using invalid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(anyError)

		var err = accountComponent.checkGLN(ctx, newGLN, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("Using valid GLN", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		mocks.glnVerifier.EXPECT().ValidateGLN(firstName, lastName, gln).Return(nil)

		var err = accountComponent.checkGLN(ctx, newGLN, &kcUser)
		assert.Nil(t, err)
	})
	t.Run("No change asked for GLN field", func(t *testing.T) {
		kcUser.SetAttributeString(constants.AttrbBusinessID, gln)

		var err = accountComponent.checkGLN(ctx, noGLNChange, &kcUser)
		assert.Nil(t, err)
	})
}

func TestGetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var accountComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"
	var userID = "1234-7454-4516"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)

	t.Run("Call to Keycloak fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, anyError)
		_, err := accountComponent.GetAccount(ctx)

		assert.NotNil(t, err)
	})

	t.Run("Retrieve checks fails", func(t *testing.T) {
		var dbError = errors.New("db error")
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kc.UserRepresentation{}, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, userID).Return([]accreditationsclient.CheckRepresentation{}, dbError)
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
	var now = time.Now().UTC()
	var createdTimestamp = now.Unix()
	var locale = "it"
	var birthLocation = "Luzern"
	var nationality = "CH"
	var docType = "PASSPORT"
	var docID = "PASS123456789"
	var docExp = "31.12.2029"
	var docCountry = "CH"

	var attributes = make(kc.Attributes)
	attributes.SetString(constants.AttrbPhoneNumber, phoneNumber)
	attributes.SetString(constants.AttrbLabel, label)
	attributes.SetString(constants.AttrbGender, gender)
	attributes.SetString(constants.AttrbBirthDate, birthDate)
	attributes.SetBool(constants.AttrbPhoneNumberVerified, phoneNumberVerified)
	attributes.SetString(constants.AttrbLocale, locale)
	attributes.SetString(constants.AttrbBirthLocation, birthLocation)
	attributes.SetString(constants.AttrbNationality, nationality)
	attributes.SetString(constants.AttrbIDDocumentType, docType)
	attributes.SetString(constants.AttrbIDDocumentNumber, docID)
	attributes.SetString(constants.AttrbIDDocumentExpiration, docExp)
	attributes.SetString(constants.AttrbIDDocumentCountry, docCountry)

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
		mocks.keycloakAccountClient.EXPECT().GetAccount(accessToken, realmName).Return(kcUserRep, nil)
		mocks.accreditationsClient.EXPECT().GetPendingChecks(ctx, realmName, userID).Return([]accreditationsclient.CheckRepresentation{{
			Nature:   ptr("nature"),
			Status:   ptr("PENDING"),
			DateTime: &now,
		}}, nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "GET_DETAILS", "back-office", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

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

	var mocks = createComponentMocks(mockCtrl)
	var accountComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var realmName = "master"
	var username = "username"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)

	t.Run("Delete user with succces", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().DeleteAccount(accessToken, realmName).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(ctx, "SELF_DELETE_ACCOUNT", "self-service", gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		err := accountComponent.DeleteAccount(ctx)

		assert.Nil(t, err)
	})

	t.Run("Delete user fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().DeleteAccount(accessToken, realmName).Return(anyError)
		err := accountComponent.DeleteAccount(ctx)

		assert.NotNil(t, err)
	})
}

func TestGetCredentials(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "TOKEN=="
	var currentRealm = "master"
	var currentUserID = "1234-789"
	var anyError = errors.New("any error")

	t.Run("Get credentials with succces", func(t *testing.T) {
		var id = "1245"

		var kcCredRep = kc.CredentialRepresentation{
			ID: &id,
		}

		var kcCredsRep []kc.CredentialRepresentation
		kcCredsRep = append(kcCredsRep, kcCredRep)

		mocks.keycloakAccountClient.EXPECT().GetCredentials(accessToken, currentRealm).Return(kcCredsRep, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		apiCredsRep, err := component.GetCredentials(ctx)

		var expectedAPICredRep = api.CredentialRepresentation{
			ID: &id,
		}

		var expectedAPICredsRep []api.CredentialRepresentation
		expectedAPICredsRep = append(expectedAPICredsRep, expectedAPICredRep)

		assert.Nil(t, err)
		assert.Equal(t, expectedAPICredsRep, apiCredsRep)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetCredentials(accessToken, currentRealm).Return([]kc.CredentialRepresentation{}, anyError)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		_, err := component.GetCredentials(ctx)

		assert.NotNil(t, err)
	})
}

func TestGetCredentialRegistrators(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	var accessToken = "TOKEN=="
	var currentRealm = "master"
	var currentUserID = "1234-789"
	var anyError = errors.New("any error")

	t.Run("Get credential types with succces", func(t *testing.T) {
		var credTypes = []string{"paper", "push"}

		mocks.keycloakAccountClient.EXPECT().GetCredentialRegistrators(accessToken, currentRealm).Return(credTypes, nil)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		resCredTypes, err := component.GetCredentialRegistrators(ctx)

		assert.Nil(t, err)
		assert.Equal(t, credTypes, resCredTypes)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetCredentialRegistrators(accessToken, currentRealm).Return([]string{}, anyError)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
		ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

		_, err := component.GetCredentialRegistrators(ctx)

		assert.NotNil(t, err)
	})
}

func TestUpdateLabelCredential(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	var anyError = errors.New("any error")

	credentialID := "78945-845"
	label := "cred label"

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().UpdateLabelCredential(accessToken, realm, credentialID, label).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_UPDATE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := component.UpdateLabelCredential(ctx, credentialID, label)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().UpdateLabelCredential(accessToken, realm, credentialID, label).Return(anyError)
		err := component.UpdateLabelCredential(ctx, credentialID, label)

		assert.NotNil(t, err)
	})
}

func TestDeleteCredential(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	credentialID := "78945-845"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	var anyError = errors.New("any error")

	var passwordCred = kc.CredentialRepresentation{ID: ptr("cred-11111"), Type: ptr("password")}
	var removingMFA = kc.CredentialRepresentation{ID: &credentialID, Type: ptr("mfa")}
	var anotherMFA = kc.CredentialRepresentation{ID: ptr("cred-22222"), Type: ptr("mfa")}

	t.Run("CheckRemovableMFA fails", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().GetCredentials(accessToken, realm).Return(nil, anyError)
		err := component.DeleteCredential(ctx, credentialID)
		assert.NotNil(t, err)
	})

	var credentials = []kc.CredentialRepresentation{passwordCred, removingMFA, anotherMFA}
	mocks.keycloakAccountClient.EXPECT().GetCredentials(accessToken, realm).Return(credentials, nil).AnyTimes()

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().DeleteCredential(accessToken, realm, credentialID).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_DELETE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := component.DeleteCredential(ctx, credentialID)

		assert.Nil(t, err)
	})

	t.Run("Error", func(t *testing.T) {
		mocks.keycloakAccountClient.EXPECT().DeleteCredential(accessToken, realm, credentialID).Return(anyError)
		err := component.DeleteCredential(ctx, credentialID)

		assert.NotNil(t, err)
	})
}

func TestMoveCredential(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

	accessToken := "access token"
	realm := "sample realm"
	userID := "123-456-789"
	username := "username"
	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, userID)
	ctx = context.WithValue(ctx, cs.CtContextUsername, username)
	var anyError = errors.New("any error")

	credentialID := "78945-845"
	previousCredentialID := "6589-7841"
	{
		mocks.keycloakAccountClient.EXPECT().MoveAfter(accessToken, realm, credentialID, previousCredentialID).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_MOVE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := component.MoveCredential(ctx, credentialID, previousCredentialID)

		assert.Nil(t, err)
	}

	{
		mocks.keycloakAccountClient.EXPECT().MoveToFirst(accessToken, realm, credentialID).Return(nil)
		mocks.eventDBModule.EXPECT().ReportEvent(gomock.Any(), "SELF_MOVE_CREDENTIAL", "self-service", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

		err := component.MoveCredential(ctx, credentialID, "null")

		assert.Nil(t, err)
	}

	{
		mocks.keycloakAccountClient.EXPECT().MoveAfter(accessToken, realm, credentialID, previousCredentialID).Return(fmt.Errorf("Unexpected error"))
		err := component.MoveCredential(ctx, credentialID, previousCredentialID)

		assert.NotNil(t, err)
	}

	{
		mocks.keycloakAccountClient.EXPECT().MoveToFirst(accessToken, realm, credentialID).Return(anyError)
		err := component.MoveCredential(ctx, credentialID, "null")

		assert.NotNil(t, err)
	}

}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createComponentMocks(mockCtrl)
	var component = mocks.createComponent()

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
	var supportedLocales = []string{"fr", "en", "es"}
	var realmConfig = kc.RealmRepresentation{InternationalizationEnabled: &trueBool, SupportedLocales: &supportedLocales}
	var anyError = errors.New("any error")
	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)
	ctx = context.WithValue(ctx, cs.CtContextUserID, currentUserID)

	t.Run("Get configuration with succces", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(config, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(adminConfig, nil)
		mocks.keycloakTechnicalClient.EXPECT().GetRealm(ctx, currentRealm).Return(realmConfig, nil)

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

		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(config, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(adminConfig, nil)
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, overrideRealm).Return(configuration.RealmConfiguration{
			RedirectSuccessfulRegistrationURL: &successURL,
		}, nil)
		mocks.keycloakTechnicalClient.EXPECT().GetRealm(ctx, currentRealm).Return(realmConfig, nil)

		resConfig, err := component.GetConfiguration(ctx, overrideRealm)

		assert.Nil(t, err)
		assert.Equal(t, *config.ShowAuthenticatorsTab, *resConfig.ShowAuthenticatorsTab)
		assert.Equal(t, *config.ShowAccountDeletionButton, *resConfig.ShowAccountDeletionButton)
		assert.Equal(t, *config.ShowProfileTab, *resConfig.ShowProfileTab)
		assert.Equal(t, *config.ShowPasswordTab, *resConfig.ShowPasswordTab)
		assert.Equal(t, successURL, *resConfig.RedirectSuccessfulRegistrationURL)
	})

	t.Run("Error on GetConfiguration", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(configuration.RealmConfiguration{}, anyError)

		_, err := component.GetConfiguration(ctx, "")

		assert.NotNil(t, err)
	})
	t.Run("Error on GetAdminConfiguration", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(configuration.RealmConfiguration{}, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(configuration.RealmAdminConfiguration{}, anyError)

		_, err := component.GetConfiguration(ctx, "")

		assert.NotNil(t, err)
	})
	t.Run("Error on GetRealm", func(t *testing.T) {
		mocks.configurationDBModule.EXPECT().GetConfiguration(ctx, currentRealm).Return(config, nil)
		mocks.configurationDBModule.EXPECT().GetAdminConfiguration(ctx, currentRealm).Return(adminConfig, nil)
		mocks.keycloakTechnicalClient.EXPECT().GetRealm(ctx, currentRealm).Return(realmConfig, anyError)

		_, err := component.GetConfiguration(ctx, "")

		assert.NotNil(t, err)
	})
}

func TestSendVerify(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mocks     = createComponentMocks(mockCtrl)
		component = mocks.createComponent()

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
		mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyEmail}).Return(expected)
		var err = component.SendVerifyEmail(ctx)
		assert.Equal(t, expected, err)
	})
	t.Run("SendVerifyEmail - success", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyEmail}).Return(nil),
			mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, currentRealm,
				database.CtEventUserID, currentUserID, database.CtEventAdditionalInfo, gomock.Any()),
		)
		assert.Nil(t, component.SendVerifyEmail(ctx))
	})

	// SendVerifyPhoneNumber
	t.Run("SendVerifyPhoneNumber - fails", func(t *testing.T) {
		var expected = errors.New("kc fails")
		gomock.InOrder(
			mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyPhoneNumber}).Return(expected),
		)
		var err = component.SendVerifyPhoneNumber(ctx)
		assert.Equal(t, expected, err)
	})
	t.Run("SendVerifyPhoneNumber - success", func(t *testing.T) {
		gomock.InOrder(
			mocks.keycloakAccountClient.EXPECT().ExecuteActionsEmail(accessToken, currentRealm, []string{ActionVerifyPhoneNumber}).Return(nil),
			mocks.eventDBModule.EXPECT().ReportEvent(ctx, "ACTION_EMAIL", "self-service", database.CtEventRealmName, currentRealm,
				database.CtEventUserID, currentUserID, database.CtEventAdditionalInfo, gomock.Any()),
		)
		assert.Nil(t, component.SendVerifyPhoneNumber(ctx))
	})
}
