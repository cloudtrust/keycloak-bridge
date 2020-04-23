package statistics

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	stat_api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Parameter names
const (
	PrmRealm = "realm"

	PrmQryUnit = "unit"
	PrmQryMax = "max"
	PrmQryTimeshift = "timeshift"
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
		PrmRealm: "^[a-zA-Z0-9_-]{1,36}$",
	}

	var queryParams = map[string]string{
		PrmQryUnit:      stat_api.RegExpPeriod,
		PrmQryMax:       stat_api.RegExpNumber,
		PrmQryTimeshift: stat_api.RegExpTimeshift,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
