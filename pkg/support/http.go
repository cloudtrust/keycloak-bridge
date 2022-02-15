package support

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	prmQryEmail = "email"
)

// MakeSupportHandler make an HTTP handler for a Support endpoint.
func MakeSupportHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeSupportRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeSupportRequest gets the HTTP parameters and body content
func decodeSupportRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{}
	var queryParams = map[string]string{prmQryEmail: constants.RegExpEmail}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
