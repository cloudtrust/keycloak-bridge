package idp

import (
	"context"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

const (
	reqBody        = "body"
	prmRealm       = "realm"
	prmProvider    = "provider"
	prmMapper      = "mapper"
	prmUser        = "user"
	prmGroupName   = "groupName"
	prmAttribKey   = "attributeKey" // can be a path param or a query param
	prmAttribValue = "attributeValue"
	prmUsername    = "username"
	prmNeedRoles   = "needRoles"
)

// MakeIdpHandler make an HTTP handler for a Identity Providers endpoint.
func MakeIdpHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	return http_transport.NewServer(e,
		decodeIdpRequest,
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}

// decodeIdpRequest gets the HTTP parameters and body content
func decodeIdpRequest(ctx context.Context, req *http.Request) (any, error) {
	var pathParams = map[string]string{
		prmRealm:     constants.RegExpRealmName,
		prmProvider:  constants.RegExpName,
		prmMapper:    constants.RegExpID,
		prmUser:      constants.RegExpID,
		prmAttribKey: constants.RegExpName,
	}

	var queryParams = map[string]string{
		prmGroupName:   constants.RegExpName,
		prmAttribKey:   constants.RegExpName,
		prmAttribValue: constants.RegExpDescription,
		prmUsername:    constants.RegExpUsername,
		prmNeedRoles:   constants.RegExpBool,
	}

	return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
}
