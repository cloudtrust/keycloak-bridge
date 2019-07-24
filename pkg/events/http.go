package events

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	"github.com/go-kit/kit/endpoint"
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
		"realm":  `^[\w-]{1,36}$`,
		"userID": `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`,
	}

	var queryParams = map[string]string{
		"origin":      `^[\w-@.]{1,128}$`,
		"realmTarget": `^[\w-]{1,36}$`,
		"ctEventType": `^[\w-]{1,128}$`,
		"dateFrom":    `^\d{1,10}$`,
		"dateTo":      `^\d{1,10}$`,
		"first":       `^\d{1,10}$`,
		"max":         `^\d{1,10}$`,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
