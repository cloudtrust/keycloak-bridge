package management

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	TestEndpoint endpoint.Endpoint
}

// MakeHealthChecksEndpoint makes the HealthCheck endpoint.
func MakeTestEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		//TODO
		return nil, nil
	}
}
