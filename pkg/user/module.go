package user

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client/client"
)

/*
This is the interface that user services implement.
*/
type KeycloakModule interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

type keycloakModule struct {
	client keycloak.Client
}

func NewKeycloakModule(client keycloak.Client) KeycloakModule {
	return &keycloakModule{
		client: client,
	}
}

func (m *keycloakModule) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var representations []keycloak.UserRepresentation
	{
		var err error
		representations, err = m.client.GetUsers(realm)
		if err != nil {
			return nil, err
		}
	}
	var users []string
	{
		for _, r := range representations {
			if r.Username != nil {
				users = append(users, *r.Username)
			}
		}
	}
	return users, nil
}
