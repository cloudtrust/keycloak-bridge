package components

import (
	keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
	"context"
)

/*
This is the interface that user services implement.
 */
type Service interface {
	GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error)
}

/*
 */
func NewBasicService(client keycloak.Service) Service {
	return &basicService{
		module:client,
	}
}

type basicService struct {
	module keycloak.Service
}

func (u *basicService)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	return u.module.GetUsers(ctx, realm)
}

