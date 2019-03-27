package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/ratelimit"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	"github.com/pkg/errors"
)

// MakeManagementHandler make an HTTP handler for a Management endpoint.
func MakeManagementHandler(e endpoint.Endpoint) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeManagementRequest,
		encodeManagementReply,
		http_transport.ServerErrorEncoder(managementErrorHandler),
	)
}

// decodeManagementRequest gets the HTTP parameters and body content
func decodeManagementRequest(_ context.Context, req *http.Request) (interface{}, error) {
	var request = map[string]string{}

	// Fetch path parameter such as realm, userID, ...
	var m = mux.Vars(req)
	for _, key := range []string{"realm", "userID", "clientID", "roleID"} {
		request[key] = m[key]
	}

	request["scheme"] = getScheme(req)
	request["host"] = req.Host

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	request["body"] = buf.String()

	for _, key := range []string{"email", "firstName", "lastName", "max", "username", "client_id", "redirect_uri"} {
		if value := req.URL.Query().Get(key); value != "" {
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

// encodeManagementReply encodes the reply.
func encodeManagementReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
	switch r := rep.(type) {
	case LocationHeader:
		w.Header().Set("Location", r.URL)
		w.WriteHeader(http.StatusCreated)
		return nil
	default:
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
}

// managementErrorHandler encodes the reply when there is an error.
func managementErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	switch e := errors.Cause(err).(type) {
	case kc_client.HTTPError:
		w.WriteHeader(e.HTTPStatus)
	default:
		if err == ratelimit.ErrLimited {
			w.WriteHeader(http.StatusTooManyRequests)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
