package management

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc_client "github.com/cloudtrust/keycloak-client/v2"
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
	prmAction       = "action"
	prmQryLanguage  = "language"

	prmQryEmail         = "email"
	prmQryFirstName     = "firstName"
	prmQryLastName      = "lastName"
	prmQryUserName      = "username"
	prmQrySearch        = "search"
	prmQryClientID      = "client_id"
	prmQryRedirectURI   = "redirect_uri"
	prmQryLifespan      = "lifespan"
	prmQryGroupIDs      = "groupIds"
	prmQryFirst         = "first"
	prmQryMax           = "max"
	prmQryGroupName     = "groupName"
	prmQryRoleName      = "roleName"
	prmQryGenUsername   = "generateUsername"
	prmQryGenNameID     = "generateNameID"
	prmQryTermsOfUse    = "termsOfUse"
	prmQryRealm         = "customerRealm"
	prmQryReminder      = "reminder"
	prmQryTargetRealm   = "targetRealm"
	prmQryTargetGroupID = "targetGroupID"
	prmQryCustom1       = "custom1"
	prmQryCustom2       = "custom2"
	prmQryCustom3       = "custom3"
	prmQryCustom4       = "custom4"
	prmQryCustom5       = "custom5"
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
		prmRealm:        constants.RegExpRealmName,
		prmUserID:       constants.RegExpID,
		prmClientID:     constants.RegExpClientID,
		prmRoleID:       constants.RegExpID,
		prmGroupID:      constants.RegExpID,
		prmCredentialID: constants.RegExpID,
		prmProvider:     constants.RegExpName,
		prmAction:       constants.RegExpName,
		prmQryLanguage:  constants.RegExpLocale,
	}

	var queryParams = map[string]string{
		prmQryEmail:         constants.RegExpSearch,
		prmQryFirstName:     constants.RegExpSearch,
		prmQryLastName:      constants.RegExpSearch,
		prmQryUserName:      constants.RegExpSearch,
		prmQrySearch:        constants.RegExpSearch,
		prmQryClientID:      constants.RegExpClientID,
		prmQryRedirectURI:   constants.RegExpRedirectURI,
		prmQryLifespan:      constants.RegExpLifespan,
		prmQryGroupIDs:      constants.RegExpGroupIds,
		prmQryFirst:         constants.RegExpNumber,
		prmQryMax:           constants.RegExpNumber,
		prmQryGroupName:     constants.RegExpName,
		prmQryRoleName:      constants.RegExpName,
		prmQryGenUsername:   constants.RegExpBool,
		prmQryGenNameID:     constants.RegExpBool,
		prmQryTermsOfUse:    constants.RegExpBool,
		prmQryRealm:         constants.RegExpRealmName,
		prmQryReminder:      constants.RegExpBool,
		prmQryTargetRealm:   constants.RegExpTargetRealmName,
		prmQryTargetGroupID: constants.RegExpTargetGroupID,
		prmQryCustom1:       constants.RegExpCustomValue,
		prmQryCustom2:       constants.RegExpCustomValue,
		prmQryCustom3:       constants.RegExpCustomValue,
		prmQryCustom4:       constants.RegExpCustomValue,
		prmQryCustom5:       constants.RegExpCustomValue,
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
			w.Write([]byte(keycloakb.ComponentName + "." + constants.MsgErrUnknown))
		default:
			defaultHandler(ctx, err, w)

		}
	}
}
