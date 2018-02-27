package event

import (
	"context"
	"fmt"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	Endpoint endpoint.Endpoint
}

// MakeEventEndpoint makes the event endpoint.
func MakeEventEndpoint(c MuxComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch eventRequest := req.(type) {
		case EventRequest:
			return nil, c.Event(ctx, eventRequest.Type, eventRequest.Object)
		default:
			return nil, fmt.Errorf("request has wrong type")
		}
	}
}
