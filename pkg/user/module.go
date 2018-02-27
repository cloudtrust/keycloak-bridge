package user

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=Module=Module github.com/cloudtrust/keycloak-bridge/pkg/user Module

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client"
)

// Module is the interface of the user module.
type Module interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

type Keycloak interface {
	GetUsers(realmName string, paramKV ...string) ([]keycloak.UserRepresentation, error)
}

type module struct {
	keycloak Keycloak
}

func NewModule(keycloak Keycloak) Module {
	return &module{
		keycloak: keycloak,
	}
}

func (m *module) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var representations []keycloak.UserRepresentation
	{
		var err error
		representations, err = m.keycloak.GetUsers(realm)
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
