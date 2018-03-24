package user

import (
	"context"
	"fmt"

	"github.com/cloudtrust/keycloak-bridge/api/user/fb"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	Endpoint endpoint.Endpoint
}

// MakeGetUsersEndpoint makes the user endpoint.
func MakeGetUsersEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch r := req.(type) {
		case *fb.GetUsersRequest:
			return c.GetUsers(ctx, r)
		default:
			return nil, fmt.Errorf("wrong request type: %T", req)
		}
	}
}
