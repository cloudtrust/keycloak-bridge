package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/ratelimit"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	"github.com/pkg/errors"
)

// MakeManagementHandler make an HTTP handler for a Management endpoint.
func MakeManagementHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeManagementRequest,
		encodeManagementReply,
		http_transport.ServerErrorEncoder(managementErrorHandler(logger)),
	)
}

// decodeManagementRequest gets the HTTP parameters and body content
func decodeManagementRequest(_ context.Context, req *http.Request) (interface{}, error) {
	var request = map[string]string{}

	// Fetch path parameter such as realm, userID, ...
	var m = mux.Vars(req)
	for _, key := range []string{"realm", "userID", "clientID", "roleID", "credentialID"} {
		request[key] = m[key]
	}

	request["scheme"] = getScheme(req)
	request["host"] = req.Host

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)
	request["body"] = buf.String()

	for _, key := range []string{"email", "firstName", "lastName", "max", "username", "search", "client_id", "redirect_uri", "lifespan", "groupIds"} {
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
func managementErrorHandler(logger log.Logger) func(context.Context, error, http.ResponseWriter){
	return func(ctx context.Context, err error, w http.ResponseWriter) {
		switch e := errors.Cause(err).(type) {
		case kc_client.HTTPError:
			logger.Log("HTTPErrorHandler", e.HTTPStatus, "msg", e.Error())
			w.WriteHeader(e.HTTPStatus)
		case security.ForbiddenError:
			logger.Log("HTTPErrorHandler", http.StatusForbidden, "msg", e.Error())
			w.WriteHeader(http.StatusForbidden)
		case keycloakb.HTTPError:
			logger.Log("HTTPErrorHandler", e.Status, "msg", e.Error())
			w.WriteHeader(e.Status)
			w.Write([]byte(e.Message))
		default:
			if err == ratelimit.ErrLimited {
				logger.Log("HTTPErrorHandler", http.StatusTooManyRequests, "msg", e.Error())
				w.WriteHeader(http.StatusTooManyRequests)
			} else {
				logger.Log("HTTPErrorHandler", http.StatusInternalServerError, "msg", e.Error())
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}
