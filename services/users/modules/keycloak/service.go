package keycloak

import (
	"io"
	"context"
	keycloak "github.com/cloudtrust/keycloak-client/client"
	"github.com/pkg/errors"
)

/*
This is the interface that user services implement.
 */
type Service interface {
	GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error)
}

/*
 */
func NewBasicService(client keycloak.Client) Service {
	return &basicService{
		client:client,
	}
}

type basicService struct {
	client keycloak.Client
}

func (u *basicService)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	var representations []keycloak.UserRepresentation
	{
		var err error
		representations, err = u.client.GetUsers(realm)
		if err != nil {
			go func(){
				errc <- errors.Wrap(err, "Couldn't get users!")
				return
			}()
			return resultc, errc
		}
	}
	go func(){
		for _,r := range representations {
			resultc <- *r.Username
		}
		errc <- io.EOF
	}()
	return resultc, errc
}