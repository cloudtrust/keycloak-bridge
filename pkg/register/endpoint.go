package register

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	commonerrors "github.com/cloudtrust/common-service/errors"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	RegisterUser     endpoint.Endpoint
	RegisterCorpUser endpoint.Endpoint
	GetConfiguration endpoint.Endpoint
}

// MakeRegisterUserEndpoint endpoint creation
func MakeRegisterUserEndpoint(component Component, socialRealm string) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m[prmRealm]
		if realm == "" {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.Realm)
		}

		return registerUser(ctx, component, socialRealm, realm, m[reqBody], true)
	}
}

// MakeRegisterCorpUserEndpoint endpoint creation
func MakeRegisterCorpUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m[prmCorpRealm]

		return registerUser(ctx, component, realm, realm, m[reqBody], false)
	}
}

func registerUser(ctx context.Context, component Component, corpRealm string, realm string, body string, isSocialRealm bool) (interface{}, error) {
	var user, err = apiregister.UserFromJSON(body)
	if err != nil {
		return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
	}
	// Validate input request
	err = user.Validate(isSocialRealm)
	if err != nil {
		return "", err
	}

	return component.RegisterUser(ctx, corpRealm, realm, user)
}

// MakeGetConfigurationEndpoint endpoint creation
func MakeGetConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m[prmRealm]
		if realm == "" {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.Realm)
		}

		return component.GetConfiguration(ctx, realm)
	}
}
