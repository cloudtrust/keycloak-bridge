package mobilepkg

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetUserInformation endpoint.Endpoint
}

// MakeGetUserInformationEndpoint makes the GetUserInformation endpoint
func MakeGetUserInformationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetUserInformation(ctx)
	}
}
