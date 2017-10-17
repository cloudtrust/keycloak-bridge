package endpoints

import (
	"context"
	"github.com/pkg/errors"
	"github.com/go-kit/kit/endpoint"
	"github.com/cloudtrust/keycloak-bridge/services/events/components"
	"github.com/cloudtrust/keycloak-bridge/services/events/transport"
)


/*
Endpoints wraps a service behind a set of endpoints.
 */
type Endpoints struct {
	MakeKeycloakEventsEndpoint endpoint.Endpoint
}


/*
KeycloakEventsEndpoint returns an endpoint.
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
