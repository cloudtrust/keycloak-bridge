package endpoints

import (
	"github.com/go-kit/kit/endpoint"
	"context"
	"io"
	"github.com/pkg/errors"
	"fmt"
	"github.com/cloudtrust/keycloak-bridge/services/users/components"
)



/*
Endpoints wraps a service behind a set of endpoints.
 */
type Endpoints struct {
	GetUsersEndpoint endpoint.Endpoint
}

/*
Request for GetUsers endpoint
 */
type GetUsersRequest struct {
	realm string
}

/*
Response from GetUsers endpoint
 */
type GetUsersResponse func() (string, error)

/*
GetUsersEndpoint returns a generator of users.
This generator is a wrapper over an endpoint that can be composed upon using mids
 */
func MakeGetUsersEndpoint(s components.Service, mids ...endpoint.Middleware) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch getUsersRequest := req.(type) {
		case GetUsersRequest:
			var userc <-chan string
			var errc <-chan error
			{
				userc, errc = s.GetUsers(ctx, getUsersRequest.realm)
			}
			var secondStageEndpoint = func(ctx context.Context, req interface{}) (interface{}, error) {
				select {
				case u := <-userc:
					return u, nil
				case err := <- errc:
					return nil, err
				}
			}
			for _, m := range mids {
				secondStageEndpoint=m(secondStageEndpoint)
			}
			var response GetUsersResponse
			response = func() (string, error) {
				var user string
				{
					var i_user interface{}
					var err error
					i_user,err = secondStageEndpoint(ctx, nil)
					if err != nil {
						switch err {
						case io.EOF:
							return "", err
						default:
							return "", errors.Wrap(err, "Something went horribly wrong!")
						}
					}
					var ok bool
					user, ok = i_user.(string)
					if !ok {
						return "", errors.Wrap(err, "Unexpected value type")
					}
				}
				return user, nil
			}
			return response, nil
		default:
			return nil,errors.New("Wrong request type")
		}
	}
}


/*
Endpoints implements Service
 */
func (u *Endpoints)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	var req = GetUsersRequest{realm}
	var resp GetUsersResponse
	{
		var i_resp interface{}
		{
			var err error
			i_resp, err = u.GetUsersEndpoint(ctx, req)
			if err != nil {
				go func() {
					errc <- errors.Wrap(err, "Couldn't get users")
					return
				}()
				return resultc, errc
			}
		}
		var ok bool
		resp, ok = i_resp.(GetUsersResponse)
		if !ok {
			go func() {
				errc <- errors.New(fmt.Sprintf("Wrong return type. Expected GetUsersResponse"))
				return
			}()
			return resultc, errc
		}
	}
	go func(){
		for {
			var user string
			var err error
			user, err = resp()
			if err != nil {
				errc <- err
				close(resultc)
				close(errc)
				return
			}
			resultc <- user
		}
	}()
	return resultc, errc
}




