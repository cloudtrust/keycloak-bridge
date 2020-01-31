package register

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	commonerrors "github.com/cloudtrust/common-service/errors"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	RegisterUser     endpoint.Endpoint
	GetConfiguration endpoint.Endpoint
}

// MakeRegisterUserEndpoint endpoint creation
func MakeRegisterUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m["realm"]
		if realm == "" {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.Realm)
		}

		var user, err = apiregister.UserFromJSON(m["body"])
		if err != nil {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
		}

		return component.RegisterUser(ctx, realm, user)
	}
}

// MakeGetConfigurationEndpoint endpoint creation
func MakeGetConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m["realm"]
		if realm == "" {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.Realm)
		}

		return component.GetConfiguration(ctx, realm)
	}
}
