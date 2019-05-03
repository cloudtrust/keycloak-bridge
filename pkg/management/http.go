package management

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	http_transport "github.com/go-kit/kit/transport/http"

	"github.com/pkg/errors"
)

// MakeManagementHandler make an HTTP handler for a Management endpoint.
func MakeManagementHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	var pathParams = []string{"realm", "userID", "clientID", "roleID", "credentialID"}
	var queryParams = []string{"email", "firstName", "lastName", "username", "search", "client_id", "redirect_uri", "lifespan", "groupIds"}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		encodeManagementReply,
		http_transport.ServerErrorEncoder(managementErrorHandler(logger)),
	)
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
