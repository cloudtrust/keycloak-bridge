package account

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service"
	errrorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	UpdatePassword            endpoint.Endpoint
	GetCredentials            endpoint.Endpoint
	GetCredentialRegistrators endpoint.Endpoint
	UpdateLabelCredential     endpoint.Endpoint
	DeleteCredential          endpoint.Endpoint
	MoveCredential            endpoint.Endpoint
	GetAccount                endpoint.Endpoint
	UpdateAccount             endpoint.Endpoint
	DeleteAccount             endpoint.Endpoint
	GetConfiguration          endpoint.Endpoint
	SendVerifyEmail           endpoint.Endpoint
	SendVerifyPhoneNumber     endpoint.Endpoint
}

// UpdatePasswordBody is the definition of the expected body content of UpdatePassword method
type UpdatePasswordBody struct {
	CurrentPassword string `json:"currentPassword,omitempty"`
	NewPassword     string `json:"newPassword,omitempty"`
	ConfirmPassword string `json:"confirmPassword,omitempty"`
}

// MakeUpdatePasswordEndpoint makes the UpdatePassword endpoint to update connected user's own password.
func MakeUpdatePasswordEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.UpdatePasswordBody

		err := json.Unmarshal([]byte(m[ReqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdatePassword(ctx, body.CurrentPassword, body.NewPassword, body.ConfirmPassword)
	}
}

// MakeGetCredentialsEndpoint makes the GetCredentials endpoint to list credentials of the current user.
func MakeGetCredentialsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetCredentials(ctx)
	}
}

// MakeGetCredentialRegistratorsEndpoint make the GetCredentialRegistrators endpoint to retrieve the list of possible kind of credentials.
func MakeGetCredentialRegistratorsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetCredentialRegistrators(ctx)
	}
}

// MakeUpdateLabelCredentialEndpoint make the UpdateLabelCredential endpoint to set a new label for a credential.
func MakeUpdateLabelCredentialEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var body api.CredentialRepresentation

		err := json.Unmarshal([]byte(m[ReqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, err
		}

		if body.UserLabel == nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + msg.UserLabel)
		}

		return nil, component.UpdateLabelCredential(ctx, m[PrmCredentialID], *body.UserLabel)
	}
}

// MakeDeleteCredentialEndpoint make the DeleteCredential endpoint to delete a credential of the current user.
func MakeDeleteCredentialEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteCredential(ctx, m[PrmCredentialID])
	}
}

// MakeMoveCredentialEndpoint make the MoveCredential endpoint to change the priority of a credential of the current user.
func MakeMoveCredentialEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.MoveCredential(ctx, m[PrmCredentialID], m[PrmPrevCredentialID])
	}
}

// MakeGetAccountEndpoint makes the GetAccount endpoint to get connected user's info.
func MakeGetAccountEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetAccount(ctx)
	}
}

// MakeUpdateAccountEndpoint makes the UpdateAccount endpoint to update connected user's own info.
func MakeUpdateAccountEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.AccountRepresentation

		err := json.Unmarshal([]byte(m[ReqBody]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateAccount(ctx, body)
	}
}

// MakeDeleteAccountEndpoint makes the DeleteAccount endpoint to delete connected user.
func MakeDeleteAccountEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return nil, component.DeleteAccount(ctx)
	}
}

// MakeGetConfigurationEndpoint makes the GetConfiguration endpoint to get the config for selfservice application.
func MakeGetConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetConfiguration(ctx, m[PrmQryRealmID])
	}
}

// MakeSendVerifyEmailEndpoint makes the SendVerifyEmail endpoint
func MakeSendVerifyEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return nil, component.SendVerifyEmail(ctx)
	}
}

// MakeSendVerifyPhoneNumberEndpoint makes the SendVerifyPhoneNumber endpoint
func MakeSendVerifyPhoneNumberEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return nil, component.SendVerifyPhoneNumber(ctx)
	}
}
