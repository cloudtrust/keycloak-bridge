package keycloakb

import (
	"context"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"net/url"
	"time"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client"
)

// TrustIDAuthToken struct
type TrustIDAuthToken struct {
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
}

// ToJSON converts TrustIDAuthToken to its JSON representation
func (t TrustIDAuthToken) ToJSON() string {
	var authBytes, _ = json.Marshal(t)
	return string(authBytes)
}

type onboardingModule struct {
	keycloakClient OnboardingKeycloakClient
	keycloakURL    string
	logger         log.Logger
}

type OnboardingKeycloakClient interface {
	ExecuteActionsEmail(accessToken string, realmName string, userID string, actions []string, paramKV ...string) error
}

type OnboardingModule interface {
	GenerateAuthToken() (TrustIDAuthToken, error)
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string,
		username string, autoLoginToken TrustIDAuthToken, onboardingClientID string, onboardingRedirectURI string) error
}

// NewOnboardingModule creates an onboarding module
func NewOnboardingModule(keycloakClient OnboardingKeycloakClient, keycloakURL string, logger log.Logger) OnboardingModule {
	return &onboardingModule{
		keycloakClient: keycloakClient,
		keycloakURL:    keycloakURL,
		logger:         logger,
	}
}

// GenerateAuthToken generates a random AUTO_LOGIN_TOKEN, used to perform auto login at the end of the onboarding process
func (om *onboardingModule) GenerateAuthToken() (TrustIDAuthToken, error) {
	var bToken = make([]byte, 32)
	_, err := rand.Read(bToken)
	if err != nil {
		return TrustIDAuthToken{}, err
	}

	return TrustIDAuthToken{
		Token:     b64.StdEncoding.EncodeToString(bToken),
		CreatedAt: time.Now().Unix(),
	}, nil
}

// OnboardingAlreadyCompleted checks if the onboarding process has already been performed
func (om *onboardingModule) OnboardingAlreadyCompleted(kcUser kc.UserRepresentation) (bool, error) {
	onboardingCompleted, err := kcUser.GetAttributeBool(constants.AttrOnboardingCompleted)
	if err != nil {
		return false, err
	}

	return onboardingCompleted != nil && *onboardingCompleted, nil
}

func (om *onboardingModule) SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string,
	username string, autoLoginToken TrustIDAuthToken, onboardingClientID string, onboardingRedirectURI string) error {

	redirectURL, err := url.Parse(om.keycloakURL + "/auth/realms/" + realmName + "/protocol/openid-connect/auth")
	if err != nil {
		om.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return err
	}

	var parameters = url.Values{}
	parameters.Add("client_id", onboardingClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("trustid_auth_token", autoLoginToken.Token)
	parameters.Add("redirect_uri", onboardingRedirectURI)
	parameters.Add("login_hint", username)

	redirectURL.RawQuery = parameters.Encode()

	err = om.keycloakClient.ExecuteActionsEmail(accessToken, realmName, userID, []string{"VERIFY_EMAIL"}, "client_id", onboardingClientID, "redirect_uri", redirectURL.String())
	if err != nil {
		om.logger.Warn(ctx, "msg", "ExecuteActionsEmail failed", "err", err.Error())
		return err
	}

	return nil
}
