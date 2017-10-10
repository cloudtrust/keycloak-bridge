package components

import (
	"context"
	"github.com/pkg/errors"
	"github.com/go-kit/kit/endpoint"
)

/***********************
Keycloak Events Receiver
 **********************/



/*
Request for KeycloakEventReceiver endpoint
 */
type KeycloakEventReceiverRequest struct {
	event string
}


/*
KeycloakEventsReceiverEndpoint returns an endpoint.
 */
func MakeKeycloakEventsReceiverEndpoint(s Service) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch keycloakEventReceiverRequest := req.(type) {
		case KeycloakEventReceiverRequest:
			var response string
			var err error
			{
				response, err = s.ProcessKeycloakEvents(ctx, keycloakEventReceiverRequest.event)
			}
			return response, err
		default:
			return nil, errors.New("Wrong request type")
		}
	}
}
