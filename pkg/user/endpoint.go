package user

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	Endpoint endpoint.Endpoint
}

// MakeUserEndpoint makes the user endpoint.
// GetUsersEndpoint returns a generator of users. This generator is a wrapper over an endpoint
// that can be composed upon using mws.
func MakeUserEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch getUsersRequest := req.(type) {
		case GetUsersRequest:
			var realm = getUsersRequest.Realm
			var users, err = c.GetUsers(ctx, realm)
			var response = GetUsersResponse{Users: users}
			return response, err
		default:
			return nil, fmt.Errorf("wrong request type: %T", req)
		}
	}
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
