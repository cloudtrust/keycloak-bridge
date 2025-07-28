package account

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	account_api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Parameter names
const (
	reqBody = "body"

	prmCredentialID     = "credentialID"
	prmPrevCredentialID = "previousCredentialID"
	prmProviderAlias    = "providerAlias"

	prmQryRealmID = "realm_id"
)

// MakeAccountHandler make an HTTP handler for an Account endpoint.
func MakeAccountHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeAccountRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeAccountRequest gets the HTTP parameters and body content
func decodeAccountRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		prmCredentialID:     constants.RegExpID,
		prmPrevCredentialID: account_api.RegExpIDNullable,
		prmProviderAlias:    constants.RegExpName,
	}

	var queryParams = map[string]string{
		prmQryRealmID: constants.RegExpRealmName,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
