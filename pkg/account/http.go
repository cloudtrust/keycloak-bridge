package account

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeAccountHandler make an HTTP handler for an Account endpoint.
func MakeAccountHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeAccountRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeAccountRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		"credentialID":         account_api.RegExpID,
		"previousCredentialID": account_api.RegExpIDNullable,
	}

	var queryParams = map[string]string{
		"realm_id": account_api.RegExpRealmName,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
