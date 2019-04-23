package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/ratelimit"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

// MakeEventsHandler make an HTTP handler for an Events endpoint.
func MakeEventsHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeEventsRequest,
		encodeEventsReply,
		http_transport.ServerErrorEncoder(eventsErrorHandler),
	)
}

// decodeEventsRequest gets the HTTP parameters and body content
func decodeEventsRequest(_ context.Context, req *http.Request) (interface{}, error) {
	var request = map[string]string{}

	// Fetch path parameter such as realm, userID, ...
	var m = mux.Vars(req)
	for _, key := range []string{"realm", "userID"} {
		if v, ok := m[key]; ok {
			request[key] = v
		}
	}

	request["scheme"] = getScheme(req)
	request["host"] = req.Host

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	request["body"] = buf.String()

	for _, key := range []string{"origin", "realm", "ctEventType", "dateFrom", "dateTo", "first", "max"} {
		if value := req.URL.Query().Get(key); value != "" {
			if _, err := request[key]; err {
				return nil, keycloakb.HTTPError{
					Status:  http.StatusBadRequest,
					Message: fmt.Sprintf("Duplicated parameter %s", key),
				}
			}
			request[key] = value
		}
	}

	return request, nil
}

func getScheme(req *http.Request) string {
	var xForwardedProtoHeader = req.Header.Get("X-Forwarded-Proto")

	if xForwardedProtoHeader != "" {
		return xForwardedProtoHeader
	}

	if req.TLS == nil {
		return "http"
	}

	return "https"
}

// encodeEventsReply encodes the reply.
func encodeEventsReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
	if rep == nil {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var json, err = json.MarshalIndent(rep, "", " ")

	if err == nil {
		w.Write(json)
	}

	return nil
}

// eventsErrorHandler encodes the reply when there is an error.
func eventsErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	switch e := errors.Cause(err).(type) {
	case keycloakb.HTTPError:
		w.WriteHeader(e.Status)
		w.Write([]byte(e.Message))
	case security.ForbiddenError:
		w.WriteHeader(http.StatusForbidden)
	default:
		if err == ratelimit.ErrLimited {
			w.WriteHeader(http.StatusTooManyRequests)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
