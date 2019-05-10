package keycloakb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/security"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/ratelimit"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

// HTTPError can be returned by the API endpoints
type HTTPError struct {
	Status  int
	Message string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Status, e.Message)
}

// CreateMissingParameterError creates a HTTPResponse for an error relative to a missing mandatory parameter
func CreateMissingParameterError(name string) HTTPError {
	return HTTPError{
		Status:  http.StatusBadRequest,
		Message: fmt.Sprintf("Missing mandatory parameter %s", name),
	}
}

// DecodeEventsRequest gets the HTTP parameters and body content
func DecodeEventsRequest(_ context.Context, req *http.Request, pathParams []string, queryParams []string) (interface{}, error) {
	var request = map[string]string{}

	// Fetch path parameter such as realm, userID, ...
	var m = mux.Vars(req)
	for _, key := range pathParams {
		if v, ok := m[key]; ok {
			request[key] = v
		}
	}

	request["scheme"] = getScheme(req)
	request["host"] = req.Host

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	request["body"] = buf.String()

	for _, key := range queryParams {
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

// EncodeEventsReply encodes the reply.
func EncodeEventsReply(_ context.Context, w http.ResponseWriter, rep interface{}) error {
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

// EventsErrorHandler encodes the reply when there is an error.
func EventsErrorHandler(_ context.Context, err error, w http.ResponseWriter) {
	switch e := errors.Cause(err).(type) {
	case HTTPError:
		w.WriteHeader(e.Status)
		// You should really take care of what you are sending here : e.Message should not leak any sensitive information
		w.Write([]byte(e.Message))
	case kc_client.HTTPError:
		w.WriteHeader(e.HTTPStatus)
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
