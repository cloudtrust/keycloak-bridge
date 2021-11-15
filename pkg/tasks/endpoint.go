package tasks

import (
	"context"
	"net/http"

	cs "github.com/cloudtrust/common-service"
	commonhttp "github.com/cloudtrust/common-service/http"
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

// MakeDeleteDeniedTermsOfUseUsersEndpoint creates an endpoint for DeleteDeniedTermsOfUseUsers
func MakeDeleteDeniedTermsOfUseUsersEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return noContentResponse(component.CleanUpAccordingToExpiredTermsOfUseAcceptance(ctx))
	}
}
