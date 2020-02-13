package kyc

import (
	"context"
	"net/http"

	commonhttp "github.com/cloudtrust/common-service/http"
	"github.com/cloudtrust/common-service/log"
	apimgmt "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/go-kit/kit/endpoint"
	http_transport "github.com/go-kit/kit/transport/http"
)

// Regular expressions
const (
	RegExpUserName = apimgmt.RegExpUsername
	RegExpUserID   = apimgmt.RegExpID
	RegExpGroupIds = apimgmt.RegExpGroupIds
)

// MakeKYCHandler make an HTTP handler for the KYC endpoint.
func MakeKYCHandler(e endpoint.Endpoint, logger log.Logger) *http_transport.Server {
	pathParams := map[string]string{"userId": RegExpUserID}
	queryParams := map[string]string{
		"username": RegExpUserName,
		"groupIds": RegExpGroupIds,
	}

	return http_transport.NewServer(e,
		func(ctx context.Context, req *http.Request) (interface{}, error) {
			return commonhttp.DecodeRequest(ctx, req, pathParams, queryParams)
		},
		commonhttp.EncodeReply,
		http_transport.ServerErrorEncoder(commonhttp.ErrorHandler(logger)),
	)
}
