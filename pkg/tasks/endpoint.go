package tasks

import (
	"context"
	"net/http"

	cs "github.com/cloudtrust/common-service/v2"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions           endpoint.Endpoint
	DeleteDeniedToUUsers endpoint.Endpoint
}

var (
	respNoContent = commonhttp.GenericResponse{StatusCode: http.StatusNoContent}
)

func noContentResponse(err error) (interface{}, error) {
	if err != nil {
		return nil, err
	}
	return respNoContent, nil
}

// MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint creates an endpoint for DeleteUsersWithExpiredTermsOfUseAcceptance
func MakeDeleteUsersWithExpiredTermsOfUseAcceptanceEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return noContentResponse(component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx))
	}
}
