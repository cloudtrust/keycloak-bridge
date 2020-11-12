package keycloakb

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAuthToken(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewOnboardingKeycloakClient(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var keycloakURL = "http://keycloak.url"

	var onboardingModule = NewOnboardingModule(mockKeycloakClient, keycloakURL, mockLogger)

	token, err := onboardingModule.GenerateAuthToken()

	assert.Nil(t, err)
	assert.NotNil(t, token)
	assert.NotEmpty(t, token.ToJSON())
	assert.NotEmpty(t, token.Token)
	assert.NotEmpty(t, token.CreatedAt)
}

func TestOnboardingAlreadyCompleted(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewOnboardingKeycloakClient(mockCtrl)
	var mockLogger = log.NewNopLogger()

	var keycloakURL = "http://keycloak.url"

	var onboardingModule = NewOnboardingModule(mockKeycloakClient, keycloakURL, mockLogger)

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
		attributes.SetString(constants.AttrOnboardingCompleted, "wrong")
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.NotNil(t, err)
		assert.False(t, res)
	})

	t.Run("OnboardingCompleted is true", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrOnboardingCompleted, true)
		var kcUser = kc.UserRepresentation{
			Attributes: &attributes,
		}
		res, err := onboardingModule.OnboardingAlreadyCompleted(kcUser)

		assert.Nil(t, err)
		assert.True(t, res)
	})

	t.Run("OnboardingCompleted is false", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		attributes.SetBool(constants.AttrOnboardingCompleted, false)
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
	var mockLogger = log.NewNopLogger()

	var keycloakURL = "http://keycloak.url"
	var realmName = "realmName"
	var accessToken = "ACCESS_TOKEN"
	var userID = "135-15641-546"
	var username = "username"
	var onboardingClientID = "onboardingid"
	var onboardingRedirectURI = "http://redirect.test/test/example"
	var ctx = context.TODO()

	var onboardingModule = NewOnboardingModule(mockKeycloakClient, keycloakURL, mockLogger)
	var autoLoginToken, _ = onboardingModule.GenerateAuthToken()

	t.Run("Failed to perform ExecuteActionEmail", func(t *testing.T) {
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, userID, []string{"VERIFY_EMAIL"},
			"client_id", onboardingClientID, "redirect_uri", gomock.Any()).Return(errors.New("unexpected error")).Times(1)
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, autoLoginToken, onboardingClientID, onboardingRedirectURI)

		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		var embeddedURI = url.QueryEscape(onboardingRedirectURI)
		var token = url.QueryEscape(autoLoginToken.Token)
		var expectedFullURI = "http://keycloak.url/auth/realms/" + realmName + "/protocol/openid-connect/auth?client_id=" + onboardingClientID + "&login_hint=" + username + "&redirect_uri=" + embeddedURI + "&response_type=code&scope=openid&trustid_auth_token=" + token
		mockKeycloakClient.EXPECT().ExecuteActionsEmail(accessToken, realmName, userID, []string{"VERIFY_EMAIL"},
			"client_id", onboardingClientID, "redirect_uri", gomock.Any()).DoAndReturn(
			func(accessToken string, realmName string, userID string, actions []string, keyClientID string, clientID string, keyRedirectURI string, redirectrURI string) error {
				_, err := url.Parse(redirectrURI)
				assert.Nil(t, err)
				assert.Equal(t, expectedFullURI, redirectrURI)
				return nil
			}).Times(1)
		err := onboardingModule.SendOnboardingEmail(ctx, accessToken, realmName, userID, username, autoLoginToken, onboardingClientID, onboardingRedirectURI)

		assert.Nil(t, err)
	})

}
