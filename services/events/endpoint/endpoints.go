package endpoints

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/services/events/component"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport"
	"github.com/go-kit/kit/endpoint"
	"github.com/pkg/errors"
)

/*
Endpoints wraps a service behind a set of endpoints.
*/
type Endpoints struct {
	KeycloakEvents endpoint.Endpoint
}

/*
MakeKeycloakEventsEndpoint returns an endpoint.
*/
func MakeKeycloakEventsEndpoint(multiplexer components.MuxService) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch eventRequest := req.(type) {
		case transport.EventRequest:
			return multiplexer.Event(ctx, eventRequest.Type, eventRequest.Object)
		default:

			return nil, errors.New("Wrong request type")
		}
	}
}
