package communications

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	errrorhandler "github.com/cloudtrust/common-service/v2/errors"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	api "github.com/cloudtrust/keycloak-bridge/api/communications"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions      endpoint.Endpoint
	SendEmail       endpoint.Endpoint
	SendEmailToUser endpoint.Endpoint
	SendSMS         endpoint.Endpoint
}

// MakeSendEmailEndpoint makes the SendEmail Endpoint
func MakeSendEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.EmailRepresentation

		err := json.Unmarshal([]byte(m[reqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(true); err != nil {
			return nil, err
		}

		return commonhttp.StatusNoContent{}, component.SendEmail(ctx, m[prmRealm], body)
	}
}

// MakeSendEmailToUserEndpoint makes the SendEmailToUser Endpoint
func MakeSendEmailToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.EmailRepresentation

		err := json.Unmarshal([]byte(m[reqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(false); err != nil {
			return nil, err
		}

		return commonhttp.StatusNoContent{}, component.SendEmailToUser(ctx, m[prmRealm], m[prmUserID], body)
	}
}

// MakeSendSMSEndpoint makes the SendSMS Endpoint
func MakeSendSMSEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.SMSRepresentation

		err := json.Unmarshal([]byte(m[reqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, err
		}

		return nil, component.SendSMS(ctx, m[prmRealm], body)
	}
}
