package event

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

// MakeKeycloakEndpoint makes the KeycloakEndpoint and apply the middelwares mws and Endpoints.mws.
func (es *Endpoints) MakeKeycloakEndpoint(c MuxComponent, mws ...endpoint.Middleware) *Endpoints {
	var e endpoint.Endpoint = func(ctx context.Context, req interface{}) (interface{}, error) {
		switch eventRequest := req.(type) {
		case EventRequest:
			return c.Event(ctx, eventRequest.Type, eventRequest.Object)
		default:
			return nil, fmt.Errorf("request has wrong type")
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
