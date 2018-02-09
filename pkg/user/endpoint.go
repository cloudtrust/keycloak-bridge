package user

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	mws           []endpoint.Middleware
	FetchEndpoint endpoint.Endpoint
}

// NewEndpoints returns Endpoints with the middlware mws. MWs are used to apply middlware
// to all the endpoint in Endpoints.
func NewEndpoints(mws ...endpoint.Middleware) *Endpoints {
	var m = append([]endpoint.Middleware{}, mws...)
	return &Endpoints{
		mws: m,
	}
}

// MakeGetUsersEndpoint makes the GetUsersEndpoint and apply the middelwares mws and Endpoints.mws.
// GetUsersEndpoint returns a generator of users. This generator is a wrapper over an endpoint
// that can be composed upon using mws.
func (es *Endpoints) MakeGetUsersEndpoint(c Component, mws ...endpoint.Middleware) *Endpoints {
	var e endpoint.Endpoint = func(ctx context.Context, req interface{}) (interface{}, error) {
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
	e = es.applyMids(e, mws...)
	es.FetchEndpoint = e
	return es
}

// applyMids apply first the middlware mws, then Endpoints.mws to the endpoint.
func (es *Endpoints) applyMids(e endpoint.Endpoint, mws ...endpoint.Middleware) endpoint.Endpoint {
	for _, m := range mws {
		e = m(e)
	}
	for _, m := range es.mws {
		e = m(e)
	}
	return e
}

func (es *Endpoints) GetUsers(ctx context.Context, realm string) ([]string, error) {
	var users []string
	{
		var usersPreCast interface{}
		var err error
		usersPreCast, err = es.FetchEndpoint(ctx, nil)
		if err != nil {
			return []string{}, err
		}
		users = usersPreCast.([]string)
	}
	return users, nil
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
