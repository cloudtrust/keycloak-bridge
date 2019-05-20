package events

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/go-kit/kit/endpoint"
	log "github.com/go-kit/kit/log"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeEventsHandler make an HTTP handler for an Events endpoint.
func MakeEventsHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeEventsRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeEventsRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	pathParams := []string{"realm", "userID"}
	queryParams := []string{"origin", "realmTarget", "ctEventType", "dateFrom", "dateTo", "first", "max"}
	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
