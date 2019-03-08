package management

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/ratelimit"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
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
	for _, key := range []string{"realm", "TODO"} {
		request[key] = m[key]
	}

	return request, nil
}

// encodeManagementReply encodes the reply.
func encodeManagementReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")


	var data, ok = rep.(json.RawMessage)

	w.WriteHeader(http.StatusOK)

	if ok {
		w.Write(data)
	}

	return nil
}

// managementErrorHandler encodes the reply when there is an error.
func managementErrorHandler(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch err {
	case ratelimit.ErrLimited:
		w.WriteHeader(http.StatusTooManyRequests)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Write error.
	var reply, _ = json.MarshalIndent(map[string]string{"error": err.Error()}, "", "  ")
	w.Write(reply)
}
