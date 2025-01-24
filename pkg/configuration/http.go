package configuration

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
	prmContextKey = "context-key"
	prmRealmName  = "realm"
)

// MakeConfigurationHandler makes an HTTP handler for the configuration endpoint
func MakeConfigurationHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{prmRealmName: constants.RegExpRealmName}
	queryParams := map[string]string{prmContextKey: constants.RegExpID}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
