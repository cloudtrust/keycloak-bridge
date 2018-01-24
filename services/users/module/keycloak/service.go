package keycloak

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client/client"
)

/*
This is the interface that user services implement.
*/
type Service interface {
	GetUsers(ctx context.Context, realm string) ([]string, error)
}

/*
 */
func NewBasicService(client keycloak.Client) Service {
	return &basicService{
		client: client,
	}
}

type basicService struct {
	client keycloak.Client
}

func (u *basicService) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var representations []keycloak.UserRepresentation
	{
		var err error
		representations, err = u.client.GetUsers(realm)
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
