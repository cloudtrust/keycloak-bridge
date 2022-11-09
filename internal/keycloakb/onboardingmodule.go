package keycloakb

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// KeycloakURIProvider interface
type KeycloakURIProvider interface {
	GetBaseURI(realm string) string
}

type onboardingModule struct {
	keycloakClient      OnboardingKeycloakClient
	keycloakURIProvider KeycloakURIProvider
	replaceAccountDelay time.Duration
	mapRealmNames       map[string]string
	logger              log.Logger
}

// OnboardingKeycloakClient interface
type OnboardingKeycloakClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	DeleteUser(accessToken string, realmName, userID string) error
	ExecuteActionsEmail(accessToken string, reqRealmName string, targetRealmName string, userID string, actions []string, paramKV ...string) error
	SendEmail(accessToken string, reqRealmName string, realmName string, emailRep kc.EmailRepresentation) error
	GenerateTrustIDAuthToken(accessToken string, reqRealmName string, realmName string, userID string) (string, error)
}

//OnboardingModule interface
type OnboardingModule interface {
	OnboardingAlreadyCompleted(kc.UserRepresentation) (bool, error)
	SendOnboardingEmail(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, paramKV ...string) error
	CreateUser(ctx context.Context, accessToken, realmName, targetRealmName string, kcUser *kc.UserRepresentation) (string, error)
	ProcessAlreadyExistingUserCases(ctx context.Context, accessToken string, targetRealmName string, userEmail string, requestingSource string, handler func(username string, createdTimestamp int64, thirdParty *string) error) error
	ComputeRedirectURI(ctx context.Context, accessToken string, realmName string, userID string, username string,
		onboardingClientID string, onboardingRedirectURI string) (string, error)
}

// NewOnboardingModule creates an onboarding module
func NewOnboardingModule(keycloakClient OnboardingKeycloakClient, keycloakURIProvider KeycloakURIProvider, replaceAccountDelay time.Duration, mapRealmNames map[string]string, logger log.Logger) OnboardingModule {
	return &onboardingModule{
		keycloakClient:      keycloakClient,
		keycloakURIProvider: keycloakURIProvider,
		replaceAccountDelay: replaceAccountDelay,
		mapRealmNames:       mapRealmNames,
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
	onboardingClientID string, onboardingRedirectURI string, themeRealmName string, reminder bool, paramKV ...string) error {
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
	additionalParams = append(additionalParams, paramKV...)
	err = om.keycloakClient.ExecuteActionsEmail(accessToken, realmName, realmName, userID, actions, additionalParams...)
	if err != nil {
		om.logger.Warn(ctx, "msg", "SendOnboardingEmail failed", "err", err.Error())
		return err
	}

	return nil
}

func (om *onboardingModule) ComputeRedirectURI(ctx context.Context, accessToken string, realmName string, userID string, username string,
	onboardingClientID string, onboardingRedirectURI string) (string, error) {
	var kcURL = fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth", om.keycloakURIProvider.GetBaseURI(realmName), realmName)
	redirectURL, err := url.Parse(kcURL)
	if err != nil {
		om.logger.Warn(ctx, "msg", "Can't parse keycloak URL", "err", err.Error())
		return "", err
	}

	trustIDAuthToken, err := om.keycloakClient.GenerateTrustIDAuthToken(accessToken, realmName, realmName, userID)
	if err != nil {
		om.logger.Warn(ctx, "msg", "Failed to generate a trustIDAuthToken", "err", err.Error())
		return "", err
	}

	var parameters = url.Values{}
	parameters.Add("client_id", onboardingClientID)
	parameters.Add("scope", "openid")
	parameters.Add("response_type", "code")
	parameters.Add("redirect_uri", onboardingRedirectURI)
	parameters.Add("login_hint", username)
	parameters.Add("trustid_auth_token", trustIDAuthToken)

	redirectURL.RawQuery = parameters.Encode()
	return redirectURL.String(), nil
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

func (om *onboardingModule) ProcessAlreadyExistingUserCases(ctx context.Context, accessToken string, targetRealmName string, userEmail string,
	requestingSource string, handler func(username string, createdTimestamp int64, thirdParty *string) error) error {
	kcUser, err := om.getUserByEmailIfDuplicateNotAllowed(ctx, accessToken, targetRealmName, userEmail)
	if err != nil {
		return err
	}

	// If user already exists...
	if kcUser != nil {
		alreadyOnboarded, err := om.OnboardingAlreadyCompleted(*kcUser)
		if err != nil {
			om.logger.Warn(ctx, "msg", "Invalid OnboardingCompleted attribute for user", "userID", kcUser.ID, "err", err.Error())
			return err
		}

		// Error if user is already onboarded
		if alreadyOnboarded {
			return handler(*kcUser.Username, *kcUser.CreatedTimestamp, nil)
		}

		if attrb := kcUser.GetAttributeString(constants.AttrbSource); !om.canReplaceAccount(*kcUser.CreatedTimestamp, attrb, requestingSource) {
			return handler(*kcUser.Username, *kcUser.CreatedTimestamp, attrb)
		}

		// Else delete this not fully onboarded user to be able to perform a fully new onboarding
		err = om.keycloakClient.DeleteUser(accessToken, targetRealmName, *kcUser.ID)
		if err != nil {
			om.logger.Warn(ctx, "msg", "Failed to delete user", "userID", *kcUser.ID, "err", err.Error())
			return err
		}
		return nil
	}
	return nil
}

func (om *onboardingModule) canReplaceAccount(createdTimestamp int64, attrb *string, requestingSource string) bool {
	// check delay
	var expirationTime = time.Unix(createdTimestamp, 0).Add(om.replaceAccountDelay)
	if expirationTime.Before(time.Now()) {
		// Account is not fully onboarded but is old enough to be inconditionaly replaced
		return true
	}
	// check source
	if attrb != nil && *attrb != "register" && om.overrideRealmName(*attrb) != om.overrideRealmName(requestingSource) {
		// Account can't be replaced if it was created by a source which is not register nor the realm of the requester
		return false
	}
	return true
}

func (om *onboardingModule) overrideRealmName(realm string) string {
	if override, ok := om.mapRealmNames[realm]; ok {
		return override
	}
	return realm
}

func (om *onboardingModule) getUserByEmailIfDuplicateNotAllowed(ctx context.Context, accessToken string, realmName string, email string) (*kc.UserRepresentation, error) {
	var kcRealm, err = om.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		om.logger.Info(ctx, "msg", "Can't get realm from Keycloak", "err", err.Error(), "realm", realmName)
		return nil, err
	}

	if kcRealm.DuplicateEmailsAllowed != nil && *kcRealm.DuplicateEmailsAllowed {
		// Duplicate email is allowed in the realm... don't need to check if email is already in use
		return nil, nil
	}

	// Add '=' at beginning of the email address to ensure that GetUsers retrieves an account with the exact provided email address
	kcUsers, err := om.keycloakClient.GetUsers(accessToken, realmName, realmName, "email", "="+email)
	if err != nil {
		om.logger.Warn(ctx, "msg", "Can't get user from keycloak", "err", err.Error())
		return nil, err
	}

	if kcUsers.Count == nil || *kcUsers.Count == 0 {
		return nil, nil
	}

	kcUser := kcUsers.Users[0]
	ConvertLegacyAttribute(&kcUser)

	return &kcUser, nil
}
