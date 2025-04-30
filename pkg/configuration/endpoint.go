package configuration

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints struct
type Endpoints struct {
	GetIdentificationURI endpoint.Endpoint
}

// MakeGetIdentificationURIEndpoint creates an endpoint for GetIdentificationURI
func MakeGetIdentificationURIEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		m := req.(map[string]string)

		return component.GetIdentificationURI(ctx, m[prmRealmName], m[prmContextKey])
	}
}
