package register

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	commonerrors "github.com/cloudtrust/common-service/v2/errors"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	"github.com/cloudtrust/common-service/v2/log"
	apiregister "github.com/cloudtrust/keycloak-bridge/api/register"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

const (
	apiName = "register"
)

// Endpoints for self service
type Endpoints struct {
	RegisterUser       endpoint.Endpoint
	RegisterCorpUser   endpoint.Endpoint
	GetConfiguration   endpoint.Endpoint
	GetUserProfile     endpoint.Endpoint
	GetCorpUserProfile endpoint.Endpoint
}

// MakeRegisterUserEndpoint endpoint creation
func MakeRegisterUserEndpoint(component Component, socialRealm string, profileCache UserProfileCache, logger log.Logger) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var realm = m[prmRealm]
		if realm == "" {
			return "", commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.Realm)
		}

		var contextKey *string
		if value, ok := m[prmContextKey]; ok {
			contextKey = &value
		}

		return registerUser(ctx, component, profileCache, logger, socialRealm, realm, m[reqBody], contextKey)
	}
}

// MakeRegisterCorpUserEndpoint endpoint creation
func MakeRegisterCorpUserEndpoint(component Component, profileCache UserProfileCache, logger log.Logger) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var realm = m[prmCorpRealm]

		var contextKey *string
		if value, ok := m[prmContextKey]; ok {
			contextKey = &value
		}

		return registerUser(ctx, component, profileCache, logger, realm, realm, m[reqBody], contextKey)
	}
}

func registerUser(ctx context.Context, component Component, profileCache UserProfileCache, logger log.Logger, corpRealm string, realm string, body string, contextKey *string) (any, error) {
	var user, err = apiregister.UserFromJSON(body)
	if err != nil {
		return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
	}
	// Validate input request
	if err = user.Validate(ctx, profileCache, realm); err != nil {
		logger.Warn(ctx, "msg", "Can't validate input", "err", err.Error())
		return "", err
	}

	redirectURL, err := component.RegisterUser(ctx, corpRealm, realm, user, contextKey)
	if err != nil {
		return nil, err
	}
	if redirectURL != "" {
		return redirectURL, nil
	}
	return commonhttp.StatusNoContent{}, nil
}

// MakeGetConfigurationEndpoint endpoint creation
func MakeGetConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var realm = req.(map[string]string)[prmRealm]
		return component.GetConfiguration(ctx, realm)
	}
}

// MakeGetUserProfileEndpoint endpoint creation
func MakeGetUserProfileEndpoint(component Component, socialRealm string) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		return component.GetUserProfile(ctx, socialRealm)
	}
}

// MakeGetCorpUserProfileEndpoint endpoint creation
func MakeGetCorpUserProfileEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var realm = req.(map[string]string)[prmCorpRealm]
		return component.GetUserProfile(ctx, realm)
	}
}
