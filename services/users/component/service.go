package components

import (
	"context"

<<<<<<< HEAD:services/users/component/service.go
	keycloak "github.com/cloudtrust/keycloak-bridge/services/users/module/keycloak"
=======
	keycloak "github.com/cloudtrust/keycloak-bridge/services/users/modules/keycloak"
>>>>>>> origin/refactor_user:services/users/components/service.go
)

/*
This is the interface that user services implement.
*/
type Service interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
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

func (u *basicService) GetUsers(ctx context.Context, realm string) ([]string, error) {
	return u.module.GetUsers(ctx, realm)
}
