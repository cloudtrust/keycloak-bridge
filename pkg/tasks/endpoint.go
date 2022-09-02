package tasks

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions           endpoint.Endpoint
	DeleteDeniedToUUsers endpoint.Endpoint
}

// MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint creates an endpoint for DeleteUsersWithExpiredTermsOfUseAcceptance
func MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return commonhttp.StatusNoContent{}, component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx)
	}
}
