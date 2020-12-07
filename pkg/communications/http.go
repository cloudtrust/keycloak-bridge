package communications

import (
	"context"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	reqScheme = "scheme"
	reqHost   = "host"
	reqBody   = "body"
	prmRealm  = "realm"
)

// MakeCommunicationsHandler make an HTTP handler for a Communications endpoint.
func MakeCommunicationsHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeCommunicationsRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeCommunicationsRequest gets the HTTP parameters and body content
func decodeCommunicationsRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		prmRealm: constants.RegExpRealmName,
	}

	var queryParams = map[string]string{}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
