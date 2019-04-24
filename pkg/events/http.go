package events

import (
	"context"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// MakeEventsHandler make an HTTP handler for an Events endpoint.
func MakeEventsHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeEventsRequest,
		keycloakb.EncodeEventsReply,
		http_transport.ServerErrorEncoder(keycloakb.EventsErrorHandler),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeEventsRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	pathParams := []string{"realm", "userID"}
	queryParams := []string{"origin", "realmTarget", "ctEventType", "dateFrom", "dateTo", "first", "max"}
	return keycloakb.DecodeEventsRequest(ctx, req, pathParams, queryParams)
}
