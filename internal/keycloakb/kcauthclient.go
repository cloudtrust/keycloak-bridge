package keycloakb

import (
	"context"

	"github.com/cloudtrust/common-service/v2/middleware"
	"github.com/cloudtrust/common-service/v2/security"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// KeycloakClient are methods from keycloak-client used by authorization manager
type KeycloakClient interface {
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	GetGroup(accessToken string, realmName, groupID string) (kc.GroupRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
}

type kcAuthClient struct {
	keycloak KeycloakClient
	logger   Logger
}

type idretriever struct {
	kcClient KeycloakClient
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
		k.logger.Warn(ctx, "msg", "Can't get group names of user", "err", err.Error(), "realm", realmName, "user", userID)
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
		k.logger.Warn(ctx, "msg", "Can't get group name", "err", err.Error(), "realm", realmName, "group", groupID)
		return "", err
	}

	if grp.Name == nil {
		return "", nil
	}

	return *(grp.Name), nil
}

// NewRealmIDRetriever is a tool use to convert a realm name in a realm ID
func NewRealmIDRetriever(kcClient KeycloakClient) middleware.IDRetriever {
	return &idretriever{
		kcClient: kcClient,
	}
}

func (ir *idretriever) GetID(accessToken, name string) (string, error) {
	var realm, err = ir.kcClient.GetRealm(accessToken, name)
	if err != nil {
		return "", err
	}
	if realm.ID == nil {
		return "", nil
	}
	return *realm.ID, nil
}
