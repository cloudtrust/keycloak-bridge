package keycloakb

import (
	"context"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/cloudtrust/keycloak-client/v2/toolbox"
)

// KeycloakTechnicalClient are methods from keycloak-client called by a technical account
type KeycloakTechnicalClient interface {
	GetRealm(ctx context.Context, realmName string) (kc.RealmRepresentation, error)
	GetUsers(ctx context.Context, realmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	LogoutAllSessions(ctx context.Context, realmName, userID string) error
	ResetPassword(ctx context.Context, realmName, userID string, cred kc.CredentialRepresentation) error
}

// KeycloakForTechnicalClient interface
type KeycloakForTechnicalClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	LogoutAllSessions(accessToken string, realmName, userID string) error
	ResetPassword(accessToken string, realmName, userID string, cred kc.CredentialRepresentation) error
}

type kcTechnicalClient struct {
	tokenProvider toolbox.OidcTokenProvider
	tokenRealm    string
	kcClient      KeycloakForTechnicalClient
	logger        Logger
}

// NewKeycloakTechnicalClient creates a Keycloak client associated to a technical user
func NewKeycloakTechnicalClient(tokenProvider toolbox.OidcTokenProvider, tokenRealm string, kcClient KeycloakForTechnicalClient, logger Logger) KeycloakTechnicalClient {
	return &kcTechnicalClient{
		tokenProvider: tokenProvider,
		tokenRealm:    tokenRealm,
		kcClient:      kcClient,
		logger:        logger,
	}
}

func (tc *kcTechnicalClient) GetRealm(ctx context.Context, realmName string) (kc.RealmRepresentation, error) {
	var accessToken, err = tc.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return kc.RealmRepresentation{}, err
	}

	return tc.kcClient.GetRealm(accessToken, realmName)
}

func (tc *kcTechnicalClient) GetUsers(ctx context.Context, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error) {
	var accessToken, err = tc.tokenProvider.ProvideTokenForRealm(ctx, targetRealmName)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return kc.UsersPageRepresentation{}, err
	}

	return tc.kcClient.GetUsers(accessToken, tc.tokenRealm, targetRealmName, paramKV...)
}

func (tc *kcTechnicalClient) LogoutAllSessions(ctx context.Context, realmName string, userID string) error {
	var accessToken, err = tc.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return err
	}

	return tc.kcClient.LogoutAllSessions(accessToken, realmName, userID)
}

func (tc *kcTechnicalClient) ResetPassword(ctx context.Context, realmName, userID string, cred kc.CredentialRepresentation) error {
	var accessToken, err = tc.tokenProvider.ProvideTokenForRealm(ctx, realmName)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return err
	}

	return tc.kcClient.ResetPassword(accessToken, realmName, userID, cred)
}
