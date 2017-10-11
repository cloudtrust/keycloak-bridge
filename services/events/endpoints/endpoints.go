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
	KeycloakEventsReceiverEndpoint endpoint.Endpoint
}


/*
KeycloakEventsReceiverEndpoint returns an endpoint.
 */
func MakeKeycloakEventsReceiverEndpoint(s components.Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch keycloakEventReceiverRequest := req.(type) {
		case transport.KeycloakEventReceiverRequest:
			s.ConsumeEvents(ctx, keycloakEventReceiverRequest.Event)
			return "ok", nil
		default:
			return nil, errors.New("Wrong request type")
		}
	}
}
