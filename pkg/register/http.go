package register

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
	reqBody = "body"

	prmCorpRealm = "corpRealm"
	prmRealm     = "realm"
	prmRedirect  = "redirect"
)

// MakeRegisterHandler make an HTTP handler for the self-register endpoint.
func MakeRegisterHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{prmCorpRealm: constants.RegExpRealmName}
	queryParams := map[string]string{
		prmRealm:    constants.RegExpRealmName,
		prmRedirect: constants.RegExpBool,
	}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
