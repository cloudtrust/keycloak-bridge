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
	var pathParams = map[string]string{
		"realm":  "^[a-zA-Z0-9_-]{1,36}$",
		"userID": "^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$",
	}

	var queryParams = map[string]string{
		"origin":      `^[a-zA-Z0-9-_@.]{1,128}$`,
		"realmTarget": `^[a-zA-Z0-9_-]{1,36}$`,
		"ctEventType": `^[a-zA-Z-_]{1,128}$`,
		"dateFrom":    `^[0-9]{1,10}$`,
		"dateTo":      `^[0-9]{1,10}$`,
		"first":       `^[0-9]{1,10}$`,
		"max":         `^[0-9]{1,10}$`,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
