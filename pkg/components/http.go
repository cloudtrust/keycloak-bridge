package components

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
	reqBody        = "body"
	prmRealmName   = "realm"
	prmComponentID = "id"
	prmQryType     = "type"
)

// MakeComponentsHandler make an HTTP handler for a Components endpoint.
func MakeComponentsHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeComponentsRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeComponentsRequest gets the HTTP parameters and body content
func decodeComponentsRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		prmRealmName:   constants.RegExpRealmName,
		prmComponentID: constants.RegExpID, // TODO
	}

	var queryParams = map[string]string{
		prmQryType: constants.RegExpSearch, // TODO
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
