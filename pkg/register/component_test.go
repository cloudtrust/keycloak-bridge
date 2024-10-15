package register

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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
	keycloakClient *mock.KeycloakClient
	tokenProvider  *mock.OidcTokenProvider
	profileCache   *mock.UserProfileCache
	configDB       *mock.ConfigurationDBModule

	eventsReporter   *mock.AuditEventsReporterModule
	glnVerifier      *mock.GlnVerifier
	contextKeyMgr    *mock.ContextKeyManager
	onboardingModule *mock.OnboardingModule
}

func createMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		keycloakClient:   mock.NewKeycloakClient(mockCtrl),
		tokenProvider:    mock.NewOidcTokenProvider(mockCtrl),
		profileCache:     mock.NewUserProfileCache(mockCtrl),
		configDB:         mock.NewConfigurationDBModule(mockCtrl),
		eventsReporter:   mock.NewAuditEventsReporterModule(mockCtrl),
		glnVerifier:      mock.NewGlnVerifier(mockCtrl),
		contextKeyMgr:    mock.NewContextKeyManager(mockCtrl),
		onboardingModule: mock.NewOnboardingModule(mockCtrl),
	}
}

func (mocks *componentMocks) createComponent() *component {
	return NewComponent(mocks.keycloakClient, mocks.tokenProvider, mocks.profileCache, mocks.configDB, mocks.eventsReporter,
		mocks.onboardingModule, mocks.glnVerifier, mocks.contextKeyMgr, log.NewNopLogger()).(*component)
}

func TestRegisterUser(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	ctx := context.TODO()
	targetRealmName := "trustid"
	customerRealmName := "customer"
	user := createValidUser()
	accessToken := "JWT_ACCESS_TOKEN"

	kcID := "98784-48764-5565"

	groupNames := []string{"group1", "group2"}
	groupID1 := "1215-651-15654"
	groupName1 := "group1"
	groupID2 := "84457-4155164-45455"
	groupName2 := "group2"
	groups := []kc.GroupRepresentation{
		{
			ID:   &groupID1,
			Name: &groupName1,
		},
		{
			ID:   &groupID2,
			Name: &groupName2,
		},
	}
	clientID := "onboardingid"
	onboardingURI := "http://test.test"
	realmConf := configuration.RealmConfiguration{
		SelfRegisterGroupNames: &groupNames,
		OnboardingClientID:     &clientID,
		OnboardingRedirectURI:  &onboardingURI,
	}
	realmAdminConf := configuration.RealmAdminConfiguration{
		SelfRegisterEnabled: ptrBool(true),
		ShowGlnEditing:      ptrBool(true),
	}
	anyError := errors.New("any error")

	errorhandler.SetEmitter(keycloakb.ComponentName)

	contextKeyNeutral := "key0"
	contextKeyRedirect := "key1"
	contextKeyInvalid := "invalid"
	mocks.contextKeyMgr.EXPECT().GetOverride(targetRealmName, contextKeyNeutral).Return(keycloakb.ContextKeyParameters{
		ID:    ptr(contextKeyRedirect),
		Realm: &customerRealmName,
	}, true).AnyTimes()
	mocks.contextKeyMgr.EXPECT().GetOverride(targetRealmName, contextKeyRedirect).Return(keycloakb.ContextKeyParameters{
		ID:           ptr(contextKeyRedirect),
		Realm:        &customerRealmName,
		RedirectMode: ptrBool(true),
	}, true).AnyTimes()

	t.Run("Failed to retrieve token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, gomock.Any()).Return("", errors.New("unexpected error"))

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})
	mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, gomock.Any()).Return(accessToken, nil).AnyTimes()

	t.Run("Failed to retrieve realm configuration", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("unexpected error"))

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, &contextKeyNeutral)
		assert.NotNil(t, err)
	})

	t.Run("Bad context key", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, realmAdminConf, nil)
		mocks.contextKeyMgr.EXPECT().GetOverride(targetRealmName, contextKeyInvalid).Return(keycloakb.ContextKeyParameters{}, false)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, &contextKeyInvalid)
		assert.NotNil(t, err)
	})

	t.Run("Feature is not enabled", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint.selfRegister", err.Error())
	})

	t.Run("Feature not configured", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(configuration.RealmConfiguration{}, realmAdminConf, nil)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
		assert.Equal(t, "409 "+keycloakb.ComponentName+".disabledEndpoint."+constants.MsgErrNotConfigured, err.Error())
	})
	mocks.configDB.EXPECT().GetConfigurations(ctx, targetRealmName).Return(realmConf, realmAdminConf, nil).AnyTimes()

	t.Run("GLN verification failed", func(t *testing.T) {
		mocks.glnVerifier.EXPECT().ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID).Return(anyError)
		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, &contextKeyNeutral)
		assert.Equal(t, anyError, err)
	})
	mocks.glnVerifier.EXPECT().ValidateGLN(*user.FirstName, *user.LastName, *user.BusinessID).Return(nil).AnyTimes()

	t.Run("Failed to compute OnboardingRedirectURI", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return("", anyError)
		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, &contextKeyNeutral)
		assert.Equal(t, anyError, err)
	})

	t.Run("Failed to process already existing user", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).Return(anyError)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	t.Run("Already existing user created by third party", func(t *testing.T) {
		username := "existing"
		var createdTimestamp int64 = 1642697516274
		thirdParty := "third-party"
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).
			DoAndReturn(func(_, _, _, _, _ interface{}, handler func(username string, createdTimestamp int64, thirdParty *string) error) error {
				return handler(username, createdTimestamp, &thirdParty)
			})
		mocks.keycloakClient.EXPECT().SendEmail(accessToken, targetRealmName, customerRealmName, gomock.Any()).Return(anyError)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	t.Run("Already onboarded user", func(t *testing.T) {
		username := "existing"
		var createdTimestamp int64 = 1642697516274
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).
			DoAndReturn(func(_, _, _, _, _ interface{}, handler func(username string, createdTimestamp int64, thirdParty *string) error) error {
				return handler(username, createdTimestamp, nil)
			})
		mocks.keycloakClient.EXPECT().SendEmail(accessToken, targetRealmName, customerRealmName, gomock.Any()).Return(anyError)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})
	mocks.onboardingModule.EXPECT().ProcessAlreadyExistingUserCases(gomock.Any(), accessToken, targetRealmName, *user.Email, "register", gomock.Any()).Return(nil).AnyTimes()

	t.Run("Failed to retrieve groups in KC", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(nil, errors.New("unexpected error"))

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	t.Run("Failed to convert all groupNames", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return([]kc.GroupRepresentation{
			{
				Name: &groupName1,
				ID:   &groupID1,
			},
		}, nil)

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	t.Run("Failed to create new user", func(t *testing.T) {
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingURI, nil)
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)
		mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any(), false).DoAndReturn(
			func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation, _ interface{}) (string, error) {
				assert.NotNil(t, kcUser.Attributes)
				return "", errors.New("unexpected error")
			})

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	mocks.onboardingModule.EXPECT().CreateUser(ctx, accessToken, targetRealmName, targetRealmName, gomock.Any(), false).DoAndReturn(
		func(_, _, _, _ interface{}, kcUser *kc.UserRepresentation, _ interface{}) (string, error) {
			assert.NotNil(t, kcUser.Attributes)
			generatedUsername := "78564513"
			kcUser.ID = &kcID
			kcUser.Username = &generatedUsername
			return "http://server/path/to/generated/resource/" + kcID, nil
		}).AnyTimes()

	t.Run("Failed to send onboarding email", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		onboardingRedirectURI := onboardingURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingRedirectURI, nil)
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), clientID, onboardingRedirectURI, customerRealmName, false, gomock.Any()).Return(errors.New("unexpected error"))

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		onboardingRedirectURI := onboardingURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingRedirectURI, nil)
		mocks.onboardingModule.EXPECT().SendOnboardingEmail(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), clientID, onboardingRedirectURI, customerRealmName, false, gomock.Any()).Return(nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		_, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, nil)
		assert.Nil(t, err)
	})

	t.Run("Success in redirect mode", func(t *testing.T) {
		expectedURL := "an-url.com"
		mocks.keycloakClient.EXPECT().GetGroups(accessToken, targetRealmName).Return(groups, nil)

		onboardingRedirectURI := onboardingURI + "?customerRealm=" + customerRealmName
		mocks.onboardingModule.EXPECT().ComputeOnboardingRedirectURI(ctx, targetRealmName, customerRealmName, realmConf).Return(onboardingRedirectURI, nil)
		mocks.onboardingModule.EXPECT().ComputeRedirectURI(ctx, accessToken, targetRealmName, kcID,
			gomock.Any(), clientID, onboardingRedirectURI).Return(expectedURL, nil)

		mocks.eventsReporter.EXPECT().ReportEvent(gomock.Any(), gomock.Any())

		url, err := component.RegisterUser(ctx, targetRealmName, customerRealmName, user, &contextKeyRedirect)
		assert.Nil(t, err)
		assert.Equal(t, expectedURL, url)
	})
}

func TestGetSupportedLocales(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	ctx := context.TODO()
	realm := "test"
	accessToken := "acce-ssto-ken!"
	supportedLocales := []string{"fr", "en"}
	realmConfig := kc.RealmRepresentation{
		SupportedLocales: &supportedLocales,
	}
	anyError := errors.New("any error")

	t.Run("Can't get access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return("", anyError)
		_, err := component.getSupportedLocales(ctx, realm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Can't get response from KC", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, anyError)
		_, err := component.getSupportedLocales(ctx, realm)
		assert.Equal(t, anyError, err)
	})
	t.Run("Internationalization disabled (nil)", func(t *testing.T) {
		realmConfig.InternationalizationEnabled = nil
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		res, err := component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Internationalization disabled (false)", func(t *testing.T) {
		bFalse := false
		realmConfig.InternationalizationEnabled = &bFalse
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		res, err := component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Internationalization enabled", func(t *testing.T) {
		bTrue := true
		realmConfig.InternationalizationEnabled = &bTrue
		mocks.tokenProvider.EXPECT().ProvideToken(ctx).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, realm).Return(realmConfig, nil)
		res, err := component.getSupportedLocales(ctx, realm)
		assert.Nil(t, err)
		assert.Len(t, *res, 2)
	})
}

func TestGetConfiguration(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	ctx := context.TODO()
	confRealm := "test"
	accessToken := "acce-ssto-ken!"
	bTrue := true
	supportedLocales := []string{"fr", "en"}
	realmConfig := kc.RealmRepresentation{
		InternationalizationEnabled: &bTrue,
		SupportedLocales:            &supportedLocales,
	}
	anyError := errors.New("any error")

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	t.Run("Get configuration from DB fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, errors.New("GetConfiguration fails"))
		_, err := component.GetConfiguration(ctx, confRealm)
		assert.NotNil(t, err)
	})
	t.Run("Get realm configuration from KC fails", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, anyError)
		_, err := component.GetConfiguration(ctx, confRealm)
		assert.Equal(t, anyError, err)
	})

	t.Run("Retrieve configuration successfully", func(t *testing.T) {
		mocks.configDB.EXPECT().GetConfigurations(gomock.Any(), gomock.Any()).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		mocks.tokenProvider.EXPECT().ProvideToken(gomock.Any()).Return(accessToken, nil)
		mocks.keycloakClient.EXPECT().GetRealm(accessToken, confRealm).Return(realmConfig, nil)
		_, err := component.GetConfiguration(ctx, confRealm)
		assert.Nil(t, err)
	})
}

func TestGetUserProfile(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	currentRealm := "my-realm"
	accessToken := "access-token"
	anyError := errors.New("any error")
	ctx := context.TODO()
	ctx = context.WithValue(ctx, cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextRealm, currentRealm)

	t.Run("Cache fails", func(t *testing.T) {
		mocks.profileCache.EXPECT().GetRealmUserProfile(ctx, currentRealm).Return(kc.UserProfileRepresentation{}, anyError)
		_, err := component.GetUserProfile(ctx, currentRealm)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.profileCache.EXPECT().GetRealmUserProfile(ctx, currentRealm).Return(kc.UserProfileRepresentation{}, nil)
		_, err := component.GetUserProfile(ctx, currentRealm)
		assert.Nil(t, err)
	})
}

func TestSendAlreadyExistsEmail(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	ctx := context.TODO()
	accessToken := "123456789-123456-4567897654"
	reqRealmName := "requester"
	realmName := "social"
	user := createValidUser()
	var creationTimestamp int64 = 1631013255392
	templateName := "template.ftl"
	username := "12345678"
	user.Username = &username

	mocks.keycloakClient.EXPECT().SendEmail(accessToken, reqRealmName, realmName, gomock.Any()).DoAndReturn(func(_, _, _ interface{}, mailInfo kc.EmailRepresentation) error {
		assert.Equal(t, templateName, *mailInfo.Theming.Template)
		assert.Equal(t, "07.09.2021", (*mailInfo.Theming.TemplateParameters)["creationDate"])
		assert.Equal(t, "13:14:15", (*mailInfo.Theming.TemplateParameters)["creationHour"])
		return nil
	})
	err := component.sendAlreadyExistsEmail(ctx, accessToken, reqRealmName, realmName, user, username, creationTimestamp, templateName)
	assert.Nil(t, err)
}
