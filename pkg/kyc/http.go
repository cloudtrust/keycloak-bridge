package kyc

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Regular expressions and parameters
const (
	RegExpUserName = constants.RegExpUsername
	RegExpUserID   = constants.RegExpID
	RegExpGroupIds = constants.RegExpGroupIds

	ReqBody = "body"

	PrmUserID = "userId"

	PrmQryUserName = "username"
)

// MakeKYCHandler make an HTTP handler for the KYC endpoint.
func MakeKYCHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{PrmUserID: RegExpUserID}
	queryParams := map[string]string{PrmQryUserName: RegExpUserName}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
