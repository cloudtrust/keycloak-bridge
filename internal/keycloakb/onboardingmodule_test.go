package keycloakb

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestOnboardingAlreadyCompleted(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewOnboardingKeycloakClient(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var onboardingModule = NewOnboardingModule(mockKeycloakClient, nil, mockLogger)

	t.Run("No attributes", func(t *testing.T) {
		var kcUser = kc.UserRepresentation{}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute missing", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetString("test", "wrong")
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted attribute with invalid value", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetString(constants.AttrbOnboardingCompleted, "wrong")
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.NotNil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted is true", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, true)
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.True(t, res)
	})

	t.Run("OnboardingCompleted is false", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrbOnboardingCompleted, false)
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.False(t, res)
	})
}

func TestSendOnboardingEmail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewOnboardingKeycloakClient(mockCtrl)
	var mockKeycloakURIProvider = mock.NewKeycloakURIProvider(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var keycloakBaseURI = "http://keycloak.url"
	var realmName = "realmName"
	var themeRealmName = "themeRealmName"
	var accessToken = "ACCESS_TOKEN"
	var userID = "135-15641-546"
	var username = "username"
	var onboardingClientID = "onboardingid"
	var onboardingRedirectURI = "http://redirect.test/test/example"
	var expectedActionsNoReminder = []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action"}
	var expectedActionsWithReminder = []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action", "reminder-action"}
	var ctx = context.TODO()

	var onboardingModule = NewOnboardingModule(mockKeycloakClient, mockKeycloakURIProvider, mockLogger)

	mockKeycloakURIProvider.EXPECT().GetBaseURI(realmName).Return(keycloakBaseURI).AnyTimes()

	t.Run("Failed to perform ExecuteActionEmail without reminder", func(t *testing.T) {
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsNoReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName).Return(errors.New("unexpected error"))
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, false, nil)

		assert.NotNil(t, err)
	})
	t.Run("Failed to perform ExecuteActionEmail with reminder", func(t *testing.T) {
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsWithReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName).Return(errors.New("unexpected error"))
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, true, nil)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var lifespan = 5400
		var embeddedURI = url.QueryEscape(onboardingRedirectURI)
		var expectedFullURI = "http://keycloak.url/auth/realms/" + realmName + "/protocol/openid-connect/auth?client_id=" + onboardingClientID + "&login_hint=" + username + "&redirect_uri=" + embeddedURI + "&response_type=code&scope=openid"
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, realmName, userID, expectedActionsNoReminder,
			"client_id", onboardingClientID, "redirect_uri", gomock.Any(), "themeRealm", themeRealmName, "lifespan", "5400").DoAndReturn(
			func(_, _, _, _ string, _ []string, _, _, _ string, redirectURI string, _, _, _, _ interface{}) error {
				_, err := url.Parse(redirectURI)
				assert.Nil(t, err)
				assert.Equal(t, expectedFullURI, redirectURI)
				return nil
			})
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, onboardingClientID, onboardingRedirectURI, themeRealmName, false, &lifespan)

		assert.Nil(t, err)
	})
}

func TestCreateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloakClient = mock.NewOnboardingKeycloakClient(mockCtrl)

	var realm = "cloudtrust"
	var targetRealm = "client"
	var ctx = context.Background()
	var accessToken = "__TOKEN__"
	var kcUser = kc.UserRepresentation{}

	var onboarding = NewOnboardingModule(mockKeycloakClient, nil, log.NewNopLogger())

	t.Run("Can't generate username", func(t *testing.T) {
		var errExistingUsername = errorhandler.Error{
			Status:  http.StatusConflict,
			Message: "keycloak.existing.username",
		}

		mockKeycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errExistingUsername).Times(10)
		var _, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "username.generation")
	})
	t.Run("User creation fails", func(t *testing.T) {
		mockKeycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return("", errors.New("any error"))
		var _, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.NotNil(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		var userID = "12345678-abcd-9876"
		var location = "http://location/users/" + userID
		kcUser.Username = nil

		mockKeycloakClient.EXPECT().CreateUser(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(location, nil)

		var resPath, err = onboarding.CreateUser(ctx, accessToken, realm, targetRealm, &kcUser)
		assert.Nil(t, err)
		var matched, errRegexp = regexp.Match(`^\d{8}$`, []byte(*kcUser.Username))
		assert.True(t, matched && errRegexp == nil)
		assert.Contains(t, resPath, *kcUser.ID)
	})
}
