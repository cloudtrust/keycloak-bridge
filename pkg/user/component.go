package user

import (
	"context"
)

type KeycloakComponent interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

type keycloakComponent struct {
	module KeycloakModule
}

func NewKeycloakComponent(module KeycloakModule) KeycloakComponent {
	return &keycloakComponent{
		module: module,
	}
}

func (c *keycloakComponent) GetUsers(ctx context.Context, realm string) ([]string, error) {
	return c.module.GetUsers(ctx, realm)
}
