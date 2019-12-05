package keycloakb

import (
	"context"

	"github.com/cloudtrust/common-service/security"
	kc "github.com/cloudtrust/keycloak-client"
)

// KeycloakClient are methods from keycloak-client used by authorization manager
type KeycloakClient interface {
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	GetGroup(accessToken string, realmName, groupID string) (kc.GroupRepresentation, error)
}

type kcAuthClient struct {
	keycloak KeycloakClient
	logger   Logger
}

// NewKeycloakAuthClient creates an adaptor for Authorization management to access Keycloak
func NewKeycloakAuthClient(client KeycloakClient, logger Logger) security.KeycloakClient {
	return &kcAuthClient{
		keycloak: client,
		logger:   logger,
	}
}

func (k *kcAuthClient) GetGroupNamesOfUser(ctx context.Context, accessToken string, realmName, userID string) ([]string, error) {
	grps, err := k.keycloak.GetGroupsOfUser(accessToken, realmName, userID)
	if err != nil {
		k.logger.Warn(ctx, "err", err.Error())
		return nil, err
	}

	if grps == nil {
		return nil, nil
	}

	var res []string
	for _, grp := range grps {
		if grp.Name != nil {
			res = append(res, *(grp.Name))
		}
	}
	return res, nil
}

func (k *kcAuthClient) GetGroupName(ctx context.Context, accessToken string, realmName, groupID string) (string, error) {
	grp, err := k.keycloak.GetGroup(accessToken, realmName, groupID)
	if err != nil {
		k.logger.Warn(ctx, "err", err.Error())
		return "", err
	}

	if grp.Name == nil {
		return "", nil
	}

	return *(grp.Name), nil
}
