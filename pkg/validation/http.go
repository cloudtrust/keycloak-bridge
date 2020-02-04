package validation

import (
	"context"
	"log"
	"net/http"

	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/go-kit/kit/endpoint"
)

// Regular expressions
const (
	RegExpUserID = api.RegExpID
)

// MakeValidationHandler make an HTTP handler for the Validation endpoint.
func MakeValidationHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{"userId": RegExpUserID}
	queryParams := map[string]string{}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
