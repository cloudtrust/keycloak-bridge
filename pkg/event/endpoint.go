package event

import (
	"context"
	"fmt"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	Endpoint endpoint.Endpoint
}

// MakeEventEndpoint makes the event endpoint.
func MakeEventEndpoint(c MuxComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		switch r := req.(type) {
		case Request:
			return nil, c.Event(ctx, r.Type, r.Object)
		default:
			return nil, fmt.Errorf(ComponentName+".wrongTypeRequest.%T", req)
		}
	}
}
