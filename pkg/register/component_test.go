package register

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func createValidUser() apiregister.UserRepresentation {
	var (
		gender        = "M"
		firstName     = "Marc"
		lastName      = "El-Bichoun"
		email         = "marcel.bichon@elca.ch"
		phoneNumber   = "00 33 686 550011"
		birthDate     = "31.03.2001"
		birthLocation = "Montreux"
		nationality   = "CH"
		docType       = "ID_CARD"
		docNumber     = "MEL123789654ABC"
		docExp        = "28.02.2050"
		docCountry    = "AT"
		locale        = "fr"
	)

	return apiregister.UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		Email:                &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		Nationality:          &nationality,
		IDDocumentType:       &docType,
		IDDocumentNumber:     &docNumber,
		IDDocumentExpiration: &docExp,
		IDDocumentCountry:    &docCountry,
		Locale:               &locale,
	}
}

func ptrString(value string) *string {
	return &value
}

func TestRegisterUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)
	var mockConfigDB = mock.NewConfigurationDBModule(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockOnboardingModule = mock.NewOnboardingModule(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var ctx = context.TODO()
	var keycloakURL = "https://idp.trustid.ch"
	var targetRealmName = "trustid"
	var customerRealmName = "customer"
	var user = createValidUser()
	var email = *user.Email
	var accessToken = "JWT_ACCESS_TOKEN"

	var count1 = 1
	var kcUsername = "78978978"
	var kcID = "98784-48764-5565"
	var reqResult = kc.UsersPageRepresentation{
		Count: &count1,
		Users: []kc.UserRepresentation{kc.UserRepresentation{
			Username: &kcUsername,
			Email:    &email,
			ID:       &kcID,
		}},
	}
	var count0 = 0
	var reqEmptyResult = kc.UsersPageRepresentation{
		Count: &count0,
		Users: nil,
	}

	var autoLoginToken = keycloakb.TrustIDAuthToken{
		Token:     "TOKEN==",
		CreatedAt: 1234,
	}
	var groupNames = []string{"group1", "group2"}
	var groupID1 = "1215-651-15654"
	var groupName1 = "group1"
	var groupID2 = "84457-4155164-45455"
	var groupName2 = "group2"
	var groups = []kc.GroupRepresentation{
		kc.GroupRepresentation{
			ID:   &groupID1,
			Name: &groupName1,
		},
		kc.GroupRepresentation{
			ID:   &groupID2,
			Name: &groupName2,
		},
	}
	var clientID = "onboardingid"
	var onboardingURI = "http://test.test"
	var realmConf = configuration.RealmConfiguration{
		SelfRegisterGroupNames: &groupNames,
		OnboardingClientID:     &clientID,
		OnboardingRedirectURI:  &onboardingURI,
	}
	var truePtr = true
	var realmAdminConf = configuration.RealmAdminConfiguration{
		SelfRegisterEnabled: &truePtr,
	}

	var component = NewComponent(keycloakURL, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, mockOnboardingModule, mockLogger)
	errorhandler.SetEmitter(keycloakb.ComponentName)

	t.Run("Failed to retrieve token", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return("", errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to retrieve realm configuration", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Feature is not enabled", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint.selfRegister", err.Error())
	})

	t.Run("Feature not configured", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, realmAdminConf, nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint."+constants.MsgErrNotConfigured, err.Error())
	})

	t.Run("Failed to search user by email", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(kc.UsersPageRepresentation{}, errors.New("unexpecte error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to check if user is already onboarded", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failure due to already onboarded user", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(true, nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
		assert.Equal(t, "400 "+keycloakb.ComponentName+"."+constants.MsgErrAlreadyOnboardedUser, err.Error())
	})

	t.Run("Failure to delete user with requested email address in KC", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failure to delete user details with requested email address in DB", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to generate auto login token", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(keycloakb.TrustIDAuthToken{}, errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to retrieve groups in KC", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(nil, errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to convert all groupNames", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return([]kc.GroupRepresentation{
			kc.GroupRepresentation{
				Name: &groupName1,
				ID:   &groupID1,
			},
		}, nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to create new user", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil).Times(1)
		mockOnboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any()).DoAndReturn(
			func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation) (string, error) {
				assert.NotNil(t, kcUser.Attributes)
				assert.Equal(t, autoLoginToken.ToJSON(), *kcUser.Attributes.GetString(constants.AttrbTrustIDAuthToken))
				return "", errors.New("unexpected error")
			}).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	mockOnboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any()).DoAndReturn(
		func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation) (string, error) {
			assert.NotNil(t, kcUser.Attributes)
			assert.Equal(t, autoLoginToken.ToJSON(), *kcUser.Attributes.GetString(constants.AttrbTrustIDAuthToken))
			var generatedUsername = "78564513"
			kcUser.ID = &kcID
			kcUser.Username = &generatedUsername
			return "http://server/path/to/generated/resource/" + kcID, nil
		}).AnyTimes()

	t.Run("Failed to store user details", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil).Times(1)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to send onboarding email", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil).Times(1)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(nil).Times(1)

		var onboardingRedirectURI = onboardingURI + "?customerRealm=" + customerRealmName
		mockOnboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), autoLoginToken, clientID, onboardingRedirectURI).Return(errors.New("unexpected error")).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Success - Email address already used by user not already onboarded", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqResult, nil).Times(1)
		mockOnboardingModule.EXPECT().OnboardingAlreadyCompleted(gomock.Any()).Return(false, nil).Times(1)
		mockKeycloakClient.EXPECT().DeleteUser(accessToken, targetRealmName, kcID).Return(nil).Times(1)
		mockUsersDB.EXPECT().DeleteUserDetails(ctx, targetRealmName, kcID).Return(nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil).Times(1)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(nil).Times(1)

		var onboardingRedirectURI = onboardingURI + "?customerRealm=" + customerRealmName
		mockOnboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), autoLoginToken, clientID, onboardingRedirectURI).Return(nil).Times(1)

		mockEventsDB.EXPECT().ReportEvent(ctx, "REGISTER_USER", "back-office", database.CtEventRealmName, targetRealmName,
			database.CtEventUserID, kcID, database.CtEventUsername, gomock.Any()).Return(nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.Nil(t, err)
	})

	t.Run("Success - Email address not used", func(t *testing.T) {
		mockTokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil).Times(1)

		mockConfigDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUsers(accessToken, targetRealmName, targetRealmName, "email", email).Return(reqEmptyResult, nil).Times(1)
		mockOnboardingModule.EXPECT().GenerateAuthToken().Return(autoLoginToken, nil).Times(1)
		mockKeycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil).Times(1)
		mockUsersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(nil).Times(1)

		mockEventsDB.EXPECT().ReportEvent(ctx, "REGISTER_USER", "back-office", database.CtEventRealmName, targetRealmName,
			database.CtEventUserID, kcID, database.CtEventUsername, gomock.Any()).Return(nil).Times(1)

		var onboardingRedirectURI = onboardingURI + "?customerRealm=" + customerRealmName
		mockOnboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), autoLoginToken, clientID, onboardingRedirectURI).Return(nil).Times(1)

		var _, err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.Nil(t, err)
	})

}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockTokenProvider = mock.NewOidcTokenProvider(mockCtrl)
	var mockConfigDB = mock.NewConfigurationDBModule(mockCtrl)
	var mockUsersDB = mock.NewUsersDetailsDBModule(mockCtrl)
	var mockEventsDB = mock.NewEventsDBModule(mockCtrl)
	var mockOnboardingModule = mock.NewOnboardingModule(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var ctx = context.TODO()
	var keycloakURL = "https://idp.trustid.ch"
	var confRealm = "test"

	var component = NewComponent(keycloakURL, mockKeycloakClient, mockTokenProvider, mockUsersDB, mockConfigDB, mockEventsDB, mockOnboardingModule, mockLogger)

	t.Run("Retrieve configuration successfully", func(t *testing.T) {
		mockConfigDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.Nil(t, err)
	})

	t.Run("Retrieve configuration in DB fails", func(t *testing.T) {
		mockConfigDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("GetConfiguration fails"))
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.NotNil(t, err)
	})
}
