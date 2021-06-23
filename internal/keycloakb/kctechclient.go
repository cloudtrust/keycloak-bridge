package keycloakb

import (
	"context"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/cloudtrust/keycloak-client/toolbox"
)

// KeycloakTechnicalClient are methods from keycloak-client called by a technical account
type KeycloakTechnicalClient interface {
	GetRealm(ctx context.Context, realmName string) (kc.RealmRepresentation, error)
	LogoutAllSessions(ctx context.Context, realmName, userID string) error
}

// KeycloakForTechnicalClient interface
type KeycloakForTechnicalClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	LogoutAllSessions(accessToken string, realmName, userID string) error
}

type kcTechnicalClient struct {
	tokenProvider toolbox.OidcTokenProvider
	kcClient      KeycloakForTechnicalClient
	logger        Logger
}

// NewKeycloakTechnicalClient creates a Keycloak client associated to a technical user
func NewKeycloakTechnicalClient(tokenProvider toolbox.OidcTokenProvider, kcClient KeycloakForTechnicalClient, logger Logger) KeycloakTechnicalClient {
	return &kcTechnicalClient{
		tokenProvider: tokenProvider,
		kcClient:      kcClient,
		logger:        logger,
	}
}

func (tc *kcTechnicalClient) GetRealm(ctx context.Context, realmName string) (kc.RealmRepresentation, error) {
	var accessToken, err = tc.tokenProvider.ProvideToken(ctx)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return kc.RealmRepresentation{}, err
	}

	return tc.kcClient.GetRealm(accessToken, realmName)
}

func (tc *kcTechnicalClient) LogoutAllSessions(ctx context.Context, realmName string, userID string) error {
	var accessToken, err = tc.tokenProvider.ProvideToken(ctx)
	if err != nil {
		tc.logger.Error(ctx, "msg", "Can't get access token", "err", err.Error())
		return err
	}

	return tc.kcClient.LogoutAllSessions(accessToken, realmName, userID)
}
