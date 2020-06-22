package validation

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Parameter names
const (
	ReqBody = "body"

	PrmRealm  = "realm"
	PrmUserID = "userID"
)

// MakeValidationHandler make an HTTP handler for a Validation endpoint.
func MakeValidationHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeManagementRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeManagementRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		PrmRealm:  api.RegExpRealmName,
		PrmUserID: api.RegExpID,
	}

	var queryParams = map[string]string{}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
