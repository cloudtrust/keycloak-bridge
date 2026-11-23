package misc

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetSupportInformation   endpoint.Endpoint
	GetCircuitBreakerStatus endpoint.Endpoint
	OpenCircuitBreaker      endpoint.Endpoint
	CloseCircuitBreaker     endpoint.Endpoint
}

// NewEndpoints creates an Endpoints instance
func NewEndpoints(component Component, endpointUpdater func(endpoint cs.Endpoint, name string) endpoint.Endpoint) Endpoints {
	return Endpoints{
		GetSupportInformation:   endpointUpdater(makeGetSupportInformationEndpoint(component), "get_email_information"),
		GetCircuitBreakerStatus: endpointUpdater(makeGetCircuitBreakerStatusEndpoint(component), "circuit_break_status"),
		OpenCircuitBreaker:      endpointUpdater(makeOpenCircuitBreakerEndpoint(component), "circuit_break_open"),
		CloseCircuitBreaker:     endpointUpdater(makeCloseCircuitBreakerEndpoint(component), "circuit_break_close"),
	}
}

// makeGetSupportInformationEndpoint creates an endpoint for GetSupportInformation
func makeGetSupportInformationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var email = req.(map[string]string)[prmQryEmail]
		if email == "" {
			return nil, errorhandler.CreateMissingParameterError(prmQryEmail)
		}
		return component.GetSupportInformation(ctx, email)
	}
}

// makeGetCircuitBreakerStatusEndpoint creates an endpoint for GetCircuitBreakerStatus
func makeGetCircuitBreakerStatusEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		m := req.(map[string]string)
		return component.GetCircuitBreakerStatus(ctx, m[prmRealm])
	}
}

// makeOpenCircuitBreakerEndpoint creates an endpoint for OpenCircuitBreaker
func makeOpenCircuitBreakerEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		m := req.(map[string]string)
		return commonhttp.StatusNoContent{}, component.OpenCircuitBreaker(ctx, m[prmRealm])
	}
}

// makeCloseCircuitBreakerEndpoint creates an endpoint for CloseCircuitBreaker
func makeCloseCircuitBreakerEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		m := req.(map[string]string)
		return commonhttp.StatusNoContent{}, component.CloseCircuitBreaker(ctx, m[prmRealm])
	}
}
