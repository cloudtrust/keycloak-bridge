package statistics

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeStatisticsHandler make an HTTP handler for a Statistics endpoint.
func MakeStatisticsHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeEventsRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeEventsRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		"realm": "^[a-zA-Z0-9_-]{1,36}$",
	}

	var queryParams = map[string]string{}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
