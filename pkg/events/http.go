package events

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	regExpDateUnix = `^\d{1,10}$`

	prmPathRealm  = "realm"
	prmPathUserID = "userID"

	prmQueryOrigin      = "origin"
	prmQueryTargetRealm = "realmTarget"
	prmQueryCtEventType = "ctEventType"
	prmQueryExclude     = "exclude"
	prmQueryDateFrom    = "dateFrom"
	prmQueryDateTo      = "dateTo"
	prmQueryFirst       = "first"
	prmQueryMax         = "max"
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
		prmPathRealm:  `^[\w-]{1,36}$`,
		prmPathUserID: `^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$`,
	}

	var queryParams = map[string]string{
		prmQueryOrigin:      `^[\w-@.]{1,128}$`,
		prmQueryTargetRealm: `^[\w-]{1,36}$`,
		prmQueryCtEventType: `^[\w-]{1,128}$`,
		prmQueryExclude:     `^[\w-]{1,128}(,[\w-]{1,128})*$`,
		prmQueryDateFrom:    regExpDateUnix,
		prmQueryDateTo:      regExpDateUnix,
		prmQueryFirst:       regExpDateUnix,
		prmQueryMax:         regExpDateUnix,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
