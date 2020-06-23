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
	reqBody   = "body"
	reqScheme = "scheme"
	reqHost   = "host"

	prmRealm        = "realm"
	prmUserID       = "userID"
	prmClientID     = "clientID"
	prmRoleID       = "roleID"
	prmGroupID      = "groupID"
	prmCredentialID = "credentialID"
	prmProvider     = "provider"

	prmQryEmail       = "email"
	prmQryFirstName   = "firstName"
	prmQryLastName    = "lastName"
	prmQryUserName    = "username"
	prmQrySearch      = "search"
	prmQryClientID    = "client_id"
	prmQryRedirectURI = "redirect_uri"
	prmQryLifespan    = "lifespan"
	prmQryGroupIDs    = "groupIds"
	prmQryFirst       = "first"
	prmQryMax         = "max"
	prmQryGroupName   = "groupName"
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
		prmRealm:        api.RegExpRealmName,
		prmUserID:       api.RegExpID,
		prmClientID:     api.RegExpClientID,
		prmRoleID:       api.RegExpID,
		prmGroupID:      api.RegExpID,
		prmCredentialID: api.RegExpID,
		prmProvider:     api.RegExpName,
	}

	var queryParams = map[string]string{
		prmQryEmail:       api.RegExpEmail,
		prmQryFirstName:   api.RegExpFirstName,
		prmQryLastName:    api.RegExpLastName,
		prmQryUserName:    api.RegExpUsername,
		prmQrySearch:      api.RegExpSearch,
		prmQryClientID:    api.RegExpClientID,
		prmQryRedirectURI: api.RegExpRedirectURI,
		prmQryLifespan:    api.RegExpLifespan,
		prmQryGroupIDs:    api.RegExpGroupIds,
		prmQryFirst:       api.RegExpNumber,
		prmQryMax:         api.RegExpNumber,
		prmQryGroupName:   api.RegExpName,
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
