package management

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/keycloak-bridge/api/management"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	http_transport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	"github.com/pkg/errors"
)

// MakeManagementHandler make an HTTP handler for a Management endpoint.
func MakeManagementHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	/*
		var pathParams = []string{"realm", "userID", "clientID", "roleID", "credentialID"}
		var queryParams = []string{"email", "firstName", "lastName", "username", "search", "client_id", "redirect_uri", "lifespan", "groupIds"}

			return http_transport.NewServer(e,
				func(ctx context.Context, req *http.Request) (interface{}, error) {
					return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
				},
				encodeManagementReply,
				http_transport.ServerErrorEncoder(managementErrorHandler(logger)),
			)
	*/

	return http_transport.NewServer(e,
		decodeManagementRequest,
		encodeManagementReply,
		http_transport.ServerErrorEncoder(managementErrorHandler(logger)),
	)
}

// decodeManagementRequest gets the HTTP parameters and body content
func decodeManagementRequest(_ context.Context, req *http.Request) (interface{}, error) {
	var request = map[string]string{}

	// Fetch and validate path parameter such as realm, userID, ...
	var pathParams = map[string]string{
		"realm":        management_api.RegExpRealmName,
		"userID":       management_api.RegExpID,
		"clientID":     management_api.RegExpID,
		"roleID":       management_api.RegExpID,
		"credentialID": management_api.RegExpID,
	}

	var m = mux.Vars(req)
	for key, validationRegExp := range pathParams {
		if v, ok := m[key]; ok {
			if matched, _ := regexp.Match(validationRegExp, []byte(v)); !matched {
				return nil, fmt.Errorf("Invalid path param: %s", key)
			}
			request[key] = m[key]
		}
	}

	request["scheme"] = getScheme(req)
	request["host"] = req.Host

	buf := new(bytes.Buffer)
	buf.ReadFrom(req.Body)

	// Input validation of body content is performed once the content is unmarshalled (Endpoint layer)
	request["body"] = buf.String()

	// Fetch and validate query parameter such as email, firstName, ...
	var queryParams = map[string]string{
		"email":        management_api.RegExpEmail,
		"firstName":    management_api.RegExpFirstName,
		"lastName":     management_api.RegExpLastName,
		"username":     management_api.RegExpUsername,
		"search":       management_api.RegExpSearch,
		"client_id":    management_api.RegExpID,
		"redirect_uri": management_api.RegExpRedirectURI,
		"lifespan":     management_api.RegExpLifespan,
		"groupIds":     management_api.RegExpGroupIds,
	}

	for key, validationRegExp := range queryParams {
		if value := req.URL.Query().Get(key); value != "" {
			if matched, _ := regexp.Match(validationRegExp, []byte(value)); !matched {
				return nil, fmt.Errorf("Invalid path param: %s", key)
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

// encodeManagementReply encodes the reply.
func encodeManagementReply(ctx context.Context, w http.ResponseWriter, rep interface{}) error {
	switch r := rep.(type) {
	case LocationHeader:
		w.Header().Set("Location", r.URL)
		w.WriteHeader(http.StatusCreated)
		return nil
	default:
		return commonhttp.EncodeReply(ctx, w, rep)
	}
}

// managementErrorHandler encodes the reply when there is an error.
func managementErrorHandler(logger log.Logger) func(context.Context, error, http.ResponseWriter) {
	defaultHandler := commonhttp.ErrorHandler(logger)
	return func(ctx context.Context, err error, w http.ResponseWriter) {
		switch e := errors.Cause(err).(type) {
		case kc_client.HTTPError:
			logger.Log("HTTPErrorHandler", e.HTTPStatus, "msg", e.Error())
			w.WriteHeader(e.HTTPStatus)
		case ConvertLocationError:
			// 201-Created, even if ConvertLocationError occurs, the creation was a success
			logger.Log("HTTPErrorHandler", http.StatusCreated, "msg", e.Error())
			w.WriteHeader(http.StatusCreated)
		default:
			defaultHandler(ctx, err, w)
		}
	}
}
