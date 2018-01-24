package endpoints

import (
	"context"
	"errors"
	"reflect"

	"github.com/cloudtrust/keycloak-bridge/services/users/component"
	"github.com/go-kit/kit/endpoint"
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
	Realm string
}

/*
Response from GetUsers endpoint
*/
type GetUsersResponse struct {
	Users []string
}

/*
GetUsersEndpoint returns a generator of users.
This generator is a wrapper over an endpoint that can be composed upon using mids
*/
func MakeGetUsersEndpoint(s components.Service, mids ...endpoint.Middleware) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch getUsersRequest := req.(type) {
		case GetUsersRequest:
			var realm = getUsersRequest.Realm
			var users, err = s.GetUsers(ctx, realm)
			var response = GetUsersResponse{
				Users: users,
			}
			return response, err
		}
		return nil, errors.New("request has wrong type " + reflect.TypeOf(req).Name())
	}
}
