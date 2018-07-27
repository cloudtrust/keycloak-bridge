package health

import (
	"context"
	"encoding/json"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	HealthCheckEndpoint endpoint.Endpoint
}

// HealthCheckers is the interface of the health check modules. It takes as parameters the context
// containing the http parameters defining which health check to execute (keys 'module' and 'healthcheck')
type HealthCheckers interface {
	HealthChecks(context.Context, map[string]string) (json.RawMessage, error)
}

// MakeHealthChecksEndpoint makes the HealthCheck endpoint.
func MakeHealthChecksEndpoint(hc HealthCheckers) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return hc.HealthChecks(ctx, m)
	}
}
