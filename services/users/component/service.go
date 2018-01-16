package components

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-bridge/services/users/module/keycloak"
)

/*
This is the interface that user services implement.
*/
type Service interface {
	GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error)
}

/*
 */
func NewBasicService(keycloakModule keycloak.Service) Service {
	return &basicService{
		module: keycloakModule,
	}
}

type basicService struct {
	module keycloak.Service
}

func (u *basicService) GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	return u.module.GetUsers(ctx, realm)
}
