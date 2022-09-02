package communications

import (
	"context"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	reqBody   = "body"
	prmRealm  = "realm"
	prmUserID = "userID"
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
		prmRealm:  constants.RegExpRealmName,
		prmUserID: constants.RegExpID,
	}

	var queryParams = map[string]string{}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
