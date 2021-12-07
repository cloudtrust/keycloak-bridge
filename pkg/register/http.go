package register

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Regular expressions and parameters
const (
	regExpRealmName = `^[a-zA-Z0-9_-]{1,36}$`

	reqBody = "body"

	prmCorpRealm = "corpRealm"
	prmRealm     = "realm"
)

// MakeRegisterHandler make an HTTP handler for the self-register endpoint.
func MakeRegisterHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{prmCorpRealm: regExpRealmName}
	queryParams := map[string]string{prmRealm: regExpRealmName}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
