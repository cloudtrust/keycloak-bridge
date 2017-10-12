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
	MakeKeycloakEventsMultiplexerEndpoint endpoint.Endpoint
}


/*
KeycloakEventsMultiplexerEndpoint returns an endpoint.
 */
func MakeKeycloakEventsMultiplexerEndpoint(multiplexer components.Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch eventMultiplexerRequest := req.(type) {
		case transport.EventMultiplexerRequest:
			return multiplexer.Event(ctx, eventMultiplexerRequest.Type, eventMultiplexerRequest.Object)
		default:
			return nil, errors.New("Wrong request type")
		}
	}
}
