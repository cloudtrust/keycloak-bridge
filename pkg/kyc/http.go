package kyc

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Regular expressions and parameters
const (
	RegExpUserName  = constants.RegExpSearch
	RegExpUserID    = constants.RegExpID
	RegExpRealmName = constants.RegExpRealmName

	reqBody = "body"

	prmRealm       = "realm"
	prmUserID      = "userID"
	prmQryUserName = "username"
	prmQryConsent  = "consent"
)

// MakeKYCHandler make an HTTP handler for the KYC endpoint.
func MakeKYCHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{prmRealm: RegExpRealmName, prmUserID: RegExpUserID}
	queryParams := map[string]string{prmQryUserName: RegExpUserName, prmQryConsent: constants.RegExpNumber}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
