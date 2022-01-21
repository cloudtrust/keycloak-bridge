package register

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/database"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
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
		gln           = "123456789"
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
		BusinessID:           &gln,
	}
}

type componentMocks struct {
	keycloakClient   *mock.KeycloakClient
	tokenProvider    *mock.OidcTokenProvider
	configDB         *mock.ConfigurationDBModule
	usersDB          *mock.UsersDetailsDBModule
	eventsDB         *mock.EventsDBModule
	glnVerifier      *mock.GlnVerifier
	onboardingModule *mock.OnboardingModule
}

func createMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient:   mock.NewKeycloakClient(mockCtrl),
		tokenProvider:    mock.NewOidcTokenProvider(mockCtrl),
		configDB:         mock.NewConfigurationDBModule(mockCtrl),
		usersDB:          mock.NewUsersDetailsDBModule(mockCtrl),
		eventsDB:         mock.NewEventsDBModule(mockCtrl),
		glnVerifier:      mock.NewGlnVerifier(mockCtrl),
		onboardingModule: mock.NewOnboardingModule(mockCtrl),
	}
}

func (mocks *componentMocks) createComponent() *component {
	return NewComponent(mocks.keycloakClient, mocks.tokenProvider, mocks.usersDB, mocks.configDB, mocks.eventsDB,
		mocks.onboardingModule, mocks.glnVerifier, log.NewNopLogger()).(*component)
}

func TestRegisterUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var ctx = context.TODO()
	var targetRealmName = "trustid"
	var customerRealmName = "customer"
	var user = createValidUser()
	var accessToken = "JWT_ACCESS_TOKEN"

	var kcID = "98784-48764-5565"

	var groupNames = []string{"group1", "group2"}
	var groupID1 = "1215-651-15654"
	var groupName1 = "group1"
	var groupID2 = "84457-4155164-45455"
	var groupName2 = "group2"
	var groups = []kc.GroupRepresentation{
		{
			ID:   &groupID1,
			Name: &groupName1,
		},
		{
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
		ShowGlnEditing:      &truePtr,
	}
	var anyError = errors.New("any error")

	errorhandler.SetEmitter(keycloakb.ComponentName)

	t.Run("Failed to retrieve token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, gomock.Any()).Return("", errors.New("unexpected error"))

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Failed to retrieve realm configuration", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("unexpected error"))

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Feature is not enabled", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint.selfRegister", err.Error())
	})

	t.Run("Feature not configured", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, realmAdminConf, nil)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint."+constants.MsgErrNotConfigured, err.Error())
	})
	mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).AnyTimes()

	t.Run("GLN verification failed", func(t *testing.T) {
		mocks.glnVerifier.EXPECT().ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID).Return(anyError)
		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.Equal(t, anyError, err)
	})
	mocks.glnVerifier.EXPECT().ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID).Return(nil).AnyTimes()

	t.Run("Failed to process already existing user", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).Return(anyError)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Already existing user created by third party", func(t *testing.T) {
		var username = "existing"
		var createdTimestamp int64 = 1642697516274
		var thirdParty = "third-party"
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).
			DoAndReturn(func(_, _, _, _, _ interface{}, handler func(username string, createdTimestamp int64, thirdParty *string) error) error {
				return handler(username, createdTimestamp, &thirdParty)
			})
		mocks.keycloakClient.EXPECT().SendEmail(accessToken, targetRealmName, customerRealmName, gomock.Any()).Return(anyError)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Already onboarded user", func(t *testing.T) {
		var username = "existing"
		var createdTimestamp int64 = 1642697516274
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).
			DoAndReturn(func(_, _, _, _, _ interface{}, handler func(username string, createdTimestamp int64, thirdParty *string) error) error {
				return handler(username, createdTimestamp, nil)
			})
		mocks.keycloakClient.EXPECT().SendEmail(accessToken, targetRealmName, customerRealmName, gomock.Any()).Return(anyError)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})
	mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).Return(nil).AnyTimes()

	t.Run("Failed to retrieve groups in KC", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(nil, errors.New("unexpected error"))

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to convert all groupNames", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return([]kc.GroupRepresentation{
			{
				Name: &groupName1,
				ID:   &groupID1,
			},
		}, nil)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to create new user", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any()).DoAndReturn(
			func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation) (string, error) {
				assert.NotNil(t, kcUser.Attributes)
				return "", errors.New("unexpected error")
			})

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any()).DoAndReturn(
		func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation) (string, error) {
			assert.NotNil(t, kcUser.Attributes)
			var generatedUsername = "78564513"
			kcUser.ID = &kcID
			kcUser.Username = &generatedUsername
			return "http://server/path/to/generated/resource/" + kcID, nil
		}).AnyTimes()

	t.Run("Failed to store user details", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(errors.New("unexpected error"))

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Failed to send onboarding email", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(nil)

		var onboardingRedirectURI = onboardingURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), clientID, onboardingRedirectURI, customerRealmName, false, gomock.Any()).Return(errors.New("unexpected error"))

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.usersDB.EXPECT().StoreOrUpdateUserDetails(ctx, targetRealmName, gomock.Any()).Return(nil)

		var onboardingRedirectURI = onboardingURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), clientID, onboardingRedirectURI, customerRealmName, false, gomock.Any()).Return(nil)

		mocks.eventsDB.EXPECT().ReportEvent(ctx, "REGISTER_USER", "back-office", database.CtEventRealmName, targetRealmName,
			database.CtEventUserID, kcID, database.CtEventUsername, gomock.Any()).Return(nil)

		var err = component.RegisterUser(ctx, targetRealmName, customerRealmName, user)
		assert.Nil(t, err)
	})
}

func TestGetSupportedLocales(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var ctx = context.TODO()
	var realm = "test"
	var accessToken = "acce-ssto-ken!"
	var supportedLocales = []string{"fr", "en"}
	var realmConfig = kc.RealmRepresentation{
		SupportedLocales: &supportedLocales,
	}
	var anyError = errors.New("any error")

	t.Run("Can't get access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)
		var _, err = component.getSupportedLocales(ctx, realm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Can't get response from KC", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, anyError)
		var _, err = component.getSupportedLocales(ctx, realm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Internationalization disabled (nil)", func(t *testing.T) {
		realmConfig.InternationalizationEnabled = nil
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		var res, err = component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Internationalization disabled (false)", func(t *testing.T) {
		var bFalse = false
		realmConfig.InternationalizationEnabled = &bFalse
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		var res, err = component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Internationalization enabled", func(t *testing.T) {
		var bTrue = true
		realmConfig.InternationalizationEnabled = &bTrue
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		var res, err = component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Len(t, *res, 2)
	})
}

func TestGetConfiguration(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var ctx = context.TODO()
	var confRealm = "test"
	var accessToken = "acce-ssto-ken!"
	var bTrue = true
	var supportedLocales = []string{"fr", "en"}
	var realmConfig = kc.RealmRepresentation{
		InternationalizationEnabled: &bTrue,
		SupportedLocales:            &supportedLocales,
	}
	var anyError = errors.New("any error")

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	t.Run("Get configuration from DB fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("GetConfiguration fails"))
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.NotNil(t, err)
	})
	t.Run("Get realm configuration from KC fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, anyError)
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.Equal(t, anyError, err)
	})

	t.Run("Retrieve configuration successfully", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, confRealm).Return(realmConfig, nil)
		var _, err = component.GetConfiguration(ctx, confRealm)
		assert.Nil(t, err)
	})
}

func TestSendAlreadyExistsEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var component = mocks.createComponent()

	var ctx = context.TODO()
	var accessToken = "123456789-123456-4567897654"
	var reqRealmName = "requester"
	var realmName = "social"
	var user = createValidUser()
	var creationTimestamp int64 = 1631013255392
	var templateName = "template.ftl"
	var username = "12345678"
	user.Username = &username

	mocks.keycloakClient.EXPECT().SendEmail(accessToken, reqRealmName, realmName, gomock.Any()).DoAndReturn(func(_, _, _ interface{}, mailInfo kc.EmailRepresentation) error {
		assert.Equal(t, templateName, *mailInfo.Theming.Template)
		assert.Equal(t, "07.09.2021", (*mailInfo.Theming.TemplateParameters)["creationDate"])
		assert.Equal(t, "13:14:15", (*mailInfo.Theming.TemplateParameters)["creationHour"])
		return nil
	})
	var err = component.sendAlreadyExistsEmail(ctx, accessToken, reqRealmName, realmName, user, username, creationTimestamp, templateName)
	assert.Nil(t, err)
}
