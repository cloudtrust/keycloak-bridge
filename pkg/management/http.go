package management

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	management_api "github.com/cloudtrust/keycloak-bridge/api/management"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"

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

// decodeEventsRequest gets the HTTP parameters and body content
func decodeManagementRequest(ctx context.Context, req *http.Request) (interface{}, error) {
	var pathParams = map[string]string{
		"realm":        management_api.RegExpRealmName,
		"userID":       management_api.RegExpID,
		"clientID":     management_api.RegExpClientID,
		"roleID":       management_api.RegExpID,
		"credentialID": management_api.RegExpID,
	}

	var queryParams = map[string]string{
		"email":        management_api.RegExpEmail,
		"firstName":    management_api.RegExpFirstName,
		"lastName":     management_api.RegExpLastName,
		"username":     management_api.RegExpUsername,
		"search":       management_api.RegExpSearch,
		"client_id":    management_api.RegExpClientID,
		"redirect_uri": management_api.RegExpRedirectURI,
		"lifespan":     management_api.RegExpLifespan,
		"groupIds":     management_api.RegExpGroupIds,
		"first":        management_api.RegExpNumber,
		"max":          management_api.RegExpNumber,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
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
			w.WriteHeader(e.HTTPStatus)
		case ConvertLocationError:
			// 201-Created, even if ConvertLocationError occurs, the creation was a success
			w.WriteHeader(http.StatusCreated)
		default:
			defaultHandler(ctx, err, w)
		}
	}
}
