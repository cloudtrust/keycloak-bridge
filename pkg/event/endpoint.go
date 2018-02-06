package event

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	mws              []endpoint.Middleware
	KeycloakEndpoint endpoint.Endpoint
}

// NewEndpoints returns Endpoints with the middlware mws. MWs are used to apply middlware
// to all the endpoint in Endpoints.
func NewEndpoints(mids ...endpoint.Middleware) *Endpoints {
	var m = append([]endpoint.Middleware{}, mws...)
	return &Endpoints{
		mws: m,
	}
}

// MakeKeycloakEndpoint makes the KeycloakEndpoint and apply the middelwares mws and Endpoints.mws.
func (es *Endpoints) MakeKeycloakEndpoint(c MuxComponent, mids ...endpoint.Middleware) *Endpoints {
	var e endpoint.Endpoint = func(ctx context.Context, req interface{}) (interface{}, error) {
		switch eventRequest := req.(type) {
		case EventRequest:
			return c.Event(ctx, eventRequest.Type, eventRequest.Object)
		default:
			return nil, fmt.Errorf("request has wrong type")
		}
	}
	e = es.applyMids(e, mids...)
	es.KeycloakEndpoint = e
	return es
}
