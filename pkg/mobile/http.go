package mobilepkg

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeMobileHandler make an HTTP handler for a Mobile endpoint.
func MakeMobileHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeAccountRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeAccountRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		// No path parameters
	}

	var queryParams = map[string]string{
		// No query parameters
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
