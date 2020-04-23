package management

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc_client "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"

	"github.com/pkg/errors"
)

// Path and query parameters
const (
	ReqBody = "body"

	PrmRealm        = "realm"
	PrmUserID       = "userID"
	PrmClientID     = "clientID"
	PrmRoleID       = "roleID"
	PrmGroupID      = "groupID"
	PrmCredentialID = "credentialID"
	PrmProvider     = "provider"

	PrmQryEmail       = "email"
	PrmQryFirstName   = "firstName"
	PrmQryLastName    = "lastName"
	PrmQryUserName    = "username"
	PrmQrySearch      = "search"
	PrmQryClientID    = "client_id"
	PrmQryRedirectURI = "redirect_uri"
	PrmQryLifespan    = "lifespan"
	PrmQryGroupIDs    = "groupIds"
	PrmQryFirst       = "first"
	PrmQryMax         = "max"
	PrmQryGroupName   = "groupName"
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
		PrmRealm:        api.RegExpRealmName,
		PrmUserID:       api.RegExpID,
		PrmClientID:     api.RegExpClientID,
		PrmRoleID:       api.RegExpID,
		PrmGroupID:      api.RegExpID,
		PrmCredentialID: api.RegExpID,
		PrmProvider:     api.RegExpName,
	}

	var queryParams = map[string]string{
		PrmQryEmail:       api.RegExpEmail,
		PrmQryFirstName:   api.RegExpFirstName,
		PrmQryLastName:    api.RegExpLastName,
		PrmQryUserName:    api.RegExpUsername,
		PrmQrySearch:      api.RegExpSearch,
		PrmQryClientID:    api.RegExpClientID,
		PrmQryRedirectURI: api.RegExpRedirectURI,
		PrmQryLifespan:    api.RegExpLifespan,
		PrmQryGroupIDs:    api.RegExpGroupIds,
		PrmQryFirst:       api.RegExpNumber,
		PrmQryMax:         api.RegExpNumber,
		PrmQryGroupName:   api.RegExpName,
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
			w.Write([]byte(keycloakb.ComponentName + "." + msg.MsgErrUnknown))
		default:
			defaultHandler(ctx, err, w)

		}
	}
}
