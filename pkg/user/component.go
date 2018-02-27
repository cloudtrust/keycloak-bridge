package user

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/user Component

import (
	"context"
)

type Component interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

type component struct {
	module Module
}

func NewComponent(module Module) Component {
	return &component{
		module: module,
	}
}

func (c *component) GetUsers(ctx context.Context, realm string) ([]string, error) {
	return c.module.GetUsers(ctx, realm)
}
