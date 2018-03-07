package user

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=Module=Module,KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/user Module,KeycloakClient

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

// Module is the interface of the user module.
type Module interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

// KeycloakClient is the interface of the keycloak client.
type KeycloakClient interface {
	GetUsers(realmName string, paramKV ...string) ([]keycloak.UserRepresentation, error)
}

type module struct {
	keycloak KeycloakClient
}

// NewModule returns a user module.
func NewModule(keycloak KeycloakClient) Module {
	return &module{
		keycloak: keycloak,
	}
}

func (m *module) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var usersRepresentation, err = m.keycloak.GetUsers(realm)
	if err != nil {
		return nil, errors.Wrapf(err, "keycloak client could not get users for realm '%v'", realm)
	}

	var users []string
	for _, r := range usersRepresentation {
		if r.Username != nil {
			users = append(users, *r.Username)
		}
	}

	return users, nil
}
