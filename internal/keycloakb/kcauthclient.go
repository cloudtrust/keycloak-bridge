package keycloakb

import (
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
}

// NewKeycloakAuthClient creates an adaptor for Authorization management to access Keycloak
func NewKeycloakAuthClient(client KeycloakClient) security.KeycloakClient {
	return &kcAuthClient{
		keycloak: client,
	}
}

func (k *kcAuthClient) GetGroupNamesOfUser(accessToken string, realmName, userID string) ([]string, error) {
	grps, err := k.keycloak.GetGroupsOfUser(accessToken, realmName, userID)
	if err != nil || grps == nil {
		return nil, err
	}
	var res []string
	for _, grp := range grps {
		if grp.Name != nil {
			res = append(res, *(grp.Name))
		}
	}
	return res, nil
}

func (k *kcAuthClient) GetGroupName(accessToken string, realmName, groupID string) (string, error) {
	grp, err := k.keycloak.GetGroup(accessToken, realmName, groupID)
	if err != nil || grp.Name == nil {
		return "", err
	}
	return *(grp.Name), nil
}
