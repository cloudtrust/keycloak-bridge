package kyc

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	commonerrors "github.com/cloudtrust/common-service/v2/errors"
	apikyc "github.com/cloudtrust/keycloak-bridge/api/kyc"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	GetActions                      endpoint.Endpoint
	GetUserInSocialRealm            endpoint.Endpoint
	GetUserByUsernameInSocialRealm  endpoint.Endpoint
	GetUser                         endpoint.Endpoint
	GetUserByUsername               endpoint.Endpoint
	ValidateUserInSocialRealm       endpoint.Endpoint
	ValidateUser                    endpoint.Endpoint
	SendSMSConsentCodeInSocialRealm endpoint.Endpoint
	SendSMSConsentCode              endpoint.Endpoint
	SendSMSCodeInSocialRealm        endpoint.Endpoint
	SendSMSCode                     endpoint.Endpoint

	ValidateUserBasic endpoint.Endpoint /***TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED***/
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetActions(ctx)
	}
}

// MakeGetUserByUsernameInSocialRealmEndpoint endpoint creation
func MakeGetUserByUsernameInSocialRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var user = m[prmQryUserName]

		return component.GetUserByUsernameInSocialRealm(ctx, user)
	}
}

// MakeGetUserByUsernameEndpoint endpoint creation
func MakeGetUserByUsernameEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m[prmRealm]
		var user = m[prmQryUserName]

		return component.GetUserByUsername(ctx, realm, user)
	}
}

// MakeGetUserInSocialRealmEndpoint endpoint creation
func MakeGetUserInSocialRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var consentCode *string

		if value, ok := m[prmQryConsent]; ok {
			consentCode = &value
		}

		return component.GetUserInSocialRealm(ctx, m[prmUserID], consentCode)
	}
}

// MakeGetUserEndpoint endpoint creation
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var consentCode *string

		if value, ok := m[prmQryConsent]; ok {
			consentCode = &value
		}

		return component.GetUser(ctx, m[prmRealm], m[prmUserID], consentCode)
	}
}

// MakeValidateUserInSocialRealmEndpoint endpoint creation
func MakeValidateUserInSocialRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var user, err = apikyc.UserFromJSON(m[reqBody])
		if err != nil {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
		}

		if err := user.Validate(false); err != nil {
			return nil, err
		}

		var consentCode *string
		if value, ok := m[prmQryConsent]; ok {
			consentCode = &value
		}

		return nil, component.ValidateUserInSocialRealm(ctx, m[prmUserID], user, consentCode)
	}
}

/********************* (BEGIN) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/
func MakeValidateUserBasicIDEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var user, err = apikyc.UserFromJSON(m[reqBody])
		if err != nil {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
		}

		if err := user.Validate(true); err != nil {
			return nil, err
		}

		return nil, component.ValidateUserBasicID(ctx, m[prmUserID], user)
	}
}

/********************* (END) Temporary basic identity (TO BE REMOVED WHEN MULTI-ACCREDITATION WILL BE IMPLEMENTED) *********************/

// MakeValidateUserEndpoint endpoint creation
func MakeValidateUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var user, err = apikyc.UserFromJSON(m[reqBody])
		if err != nil {
			return nil, commonerrors.CreateBadRequestError(commonerrors.MsgErrInvalidParam + "." + msg.BodyContent)
		}

		if err := user.Validate(false); err != nil {
			return nil, err
		}

		var consentCode *string
		if value, ok := m[prmQryConsent]; ok {
			consentCode = &value
		}

		return nil, component.ValidateUser(ctx, m[prmRealm], m[prmUserID], user, consentCode)
	}
}

// MakeSendSmsConsentCodeInSocialRealmEndpoint creates an endpoint for SendSmsConsentCodeInSocialRealm
func MakeSendSmsConsentCodeInSocialRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.SendSmsConsentCodeInSocialRealm(ctx, m[prmUserID])
	}
}

// MakeSendSmsConsentCodeEndpoint creates an endpoint for SendSmsConsentCode
func MakeSendSmsConsentCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.SendSmsConsentCode(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeSendSmsCodeInSocialRealmEndpoint creates an endpoint for SendSmsCodeInSocialRealm
func MakeSendSmsCodeInSocialRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		code, err := component.SendSmsCodeInSocialRealm(ctx, m[prmUserID])
		return map[string]string{"code": code}, err
	}
}

// MakeSendSmsCodeEndpoint creates an endpoint for SendSmsCode
func MakeSendSmsCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		code, err := component.SendSmsCode(ctx, m[prmRealm], m[prmUserID])
		return map[string]string{"code": code}, err
	}
}
