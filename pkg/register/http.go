package register

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	// RegExpRealmName is a regular expression for realm names
	RegExpRealmName = `^[a-zA-Z0-9_-]{1,36}$`
)

// MakeRegisterHandler make an HTTP handler for the self-register endpoint.
func MakeRegisterHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{"realm": RegExpRealmName}
	queryParams := map[string]string{"realm": RegExpRealmName}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
