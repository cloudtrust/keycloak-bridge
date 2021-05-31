package keycloakb

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	errorhandler "github.com/cloudtrust/common-service/errors"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client"
)

type KeycloakURIProvider interface {
	GetBaseURI(realm string) string
}

type onboardingModule struct {
	keycloakClient      OnboardingKeycloakClient
	keycloakURIProvider KeycloakURIProvider
	logger              log.Logger
}

// OnboardingKeycloakClient interface
type OnboardingKeycloakClient interface {
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	ExecuteActionsEmail(accessToken string, reqRealmName string, targetRealmName string, userID string, actions []string, paramKV ...string) error
}

//OnboardingModule interface
type OnboardingModule interface {
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, lifespan *int) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error)
}

// NewOnboardingModule creates an onboarding module
func NewOnboardingModule(keycloakClient OnboardingKeycloakClient, keycloakURIProvider KeycloakURIProvider, logger log.Logger) OnboardingModule {
	return &onboardingModule{
		keycloakClient:      keycloakClient,
		keycloakURIProvider: keycloakURIProvider,
		logger:              logger,
	}
}

// OnboardingAlreadyCompleted checks if the onboarding process has already been performed
func (om *onboardingModule) OnboardingAlreadyCompleted(kcUser kc.UserRepresentation) (bool, error) {
	onboardingCompleted, err := kcUser.GetAttributeBool(constants.AttrbOnboardingCompleted)
	if err != nil {
		return false, err
	}

	return onboardingCompleted != nil && *onboardingCompleted, nil
}

func (om *onboardingModule) SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
	onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, lifespan *int) error {
	var kcURL = fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth", om.keycloakURIProvider.GetBaseURI(realmName), realmName)
	redirectURL, err := url.Parse(kcURL)
	if err != nil {
		om.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return err
	}

	var parameters = url.Values{}
	parameters.Add("client_id", onboardingClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("redirect_uri", onboardingRedirectURI)
	parameters.Add("login_hint", username)

	redirectURL.RawQuery = parameters.Encode()

	var actions = []string{"VERIFY_EMAIL", "set-onboarding-token", "onboarding-action"}
	if reminder {
		actions = append(actions, "reminder-action")
	}
	var additionalParams = []string{"client_id", onboardingClientID, "redirect_uri", redirectURL.String(), "themeRealm", themeRealmName}
	if lifespan != nil {
		additionalParams = append(additionalParams, "lifespan", strconv.Itoa(*lifespan))
	}
	err = om.keycloakClient.ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, additionalParams...)
	if err != nil {
		om.logger.Warn(ctx, "msg", "ExecuteActionsEmail failed", "err", err.Error())
		return err
	}

	return nil
}

func (om *onboardingModule) generateUsername(chars []rune, length int) string {
	var b strings.Builder

	for j := 0; j < length; j++ {
		nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		index := int(nBig.Int64())
		b.WriteRune(chars[index])
	}
	return b.String()
}

func (om *onboardingModule) CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error) {
	var chars = []rune("0123456789")
	var locationURL string
	var username string
	var err error

	for i := 0; i < 10; i++ {
		username = om.generateUsername(chars, 8)
		kcUser.Username = &username

		locationURL, err = om.keycloakClient.CreateUser(accessToken, realmName, targetRealmName, *kcUser)

		// Create success: just have to get the userID and exit this loop
		if err == nil {
			var re = regexp.MustCompile(`(^.*/users/)`)
			var userID = re.ReplaceAllString(locationURL, "")
			kcUser.ID = &userID
			return locationURL, nil
		}
		kcUser.Username = nil

		switch e := err.(type) {
		case errorhandler.Error:
			if e.Status == http.StatusConflict && e.Message == "keycloak.existing.username" {
				// Username already exists
				continue
			}
		}
		om.logger.Warn(ctx, "msg", "Failed to create user through Keycloak API", "err", err.Error())
		return "", err
	}

	om.logger.Warn(ctx, "msg", "Can't generate unused username after multiple attempts")
	return "", errorhandler.CreateInternalServerError("username.generation")
}
