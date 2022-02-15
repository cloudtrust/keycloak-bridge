package support

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetSupportInformation endpoint.Endpoint
}

// MakeGetSupportInformationEndpoint creates an endpoint for GetSupportInformation
func MakeGetSupportInformationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var email = req.(map[string]string)[prmQryEmail]
		if email == "" {
			return nil, errorhandler.CreateMissingParameterError(prmQryEmail)
		}
		return component.GetSupportInformation(ctx, email)
	}
}
