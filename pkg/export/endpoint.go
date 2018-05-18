package export

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	Endpoint endpoint.Endpoint
}

// Component is the user component interface.
type Component interface {
	Export(ctx context.Context) (map[string]interface{}, error)
	StoreAndExport(ctx context.Context) (map[string]interface{}, error)
}

// MakeExportEndpoint makes endpoint that reads the config in DB.
func MakeExportEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.Export(ctx)
	}
}

// MakeStoreAndExportEndpoint makes the endpoint that forces the keycloak exportation and stores the config in DB.
func MakeStoreAndExportEndpoint(c Component) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return c.StoreAndExport(ctx)
	}
}
