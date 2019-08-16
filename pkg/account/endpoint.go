package account

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service"
	errors "github.com/cloudtrust/common-service/errors"
	errrorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
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
}

// UpdatePasswordBody is the definition of the expected body content of UpdatePassword method
type UpdatePasswordBody struct {
	CurrentPassword string `json:"currentPassword,omitempty"`
	NewPassword     string `json:"newPassword,omitempty"`
	ConfirmPassword string `json:"confirmPassword,omitempty"`
}

// AccountComponent describes methods of the Account API
type AccountComponent interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
	GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error)
	GetCredentialRegistrators(ctx context.Context) ([]string, error)
	UpdateLabelCredential(ctx context.Context, credentialID string, label string) error
	DeleteCredential(ctx context.Context, credentialID string) error
	MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error
	GetAccount(ctx context.Context) (api.AccountRepresentation, error)
	UpdateAccount(ctx context.Context, account api.AccountRepresentation) error
	DeleteAccount(ctx context.Context) error
}

// MakeUpdatePasswordEndpoint makes the UpdatePassword endpoint to update connected user's own password.
func MakeUpdatePasswordEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.UpdatePasswordBody

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, errrorhandler.CreateBadRequestError(err.Error())
		}

		if err = body.Validate(); err != nil {
			return nil, errors.CreateBadRequestError(err.Error())
		}

		return nil, component.UpdatePassword(ctx, body.CurrentPassword, body.NewPassword, body.ConfirmPassword)
	}
}

// MakeGetCredentialsEndpoint makes the GetCredentials endpoint to list credentials of the current user.
func MakeGetCredentialsEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetCredentials(ctx)
	}
}

// MakeGetCredentialRegistratorsEndpoint make the GetCredentialRegistrators endpoint to retrieve the list of possible kind of credentials.
func MakeGetCredentialRegistratorsEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetCredentialRegistrators(ctx)
	}
}

// MakeUpdateLabelCredentialEndpoint make the UpdateLabelCredential endpoint to set a new label for a credential.
func MakeUpdateLabelCredentialEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var body api.CredentialRepresentation

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError("Invalid body")
		}

		if err = body.Validate(); err != nil {
			return nil, errrorhandler.CreateBadRequestError(err.Error())
		}

		if body.UserLabel == nil {
			return nil, errrorhandler.CreateBadRequestError("User label missing")
		}

		return nil, component.UpdateLabelCredential(ctx, m["credentialID"], *body.UserLabel)
	}
}

// MakeDeleteCredentialEndpoint make the DeleteCredential endpoint to delete a credential of the current user.
func MakeDeleteCredentialEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteCredential(ctx, m["credentialID"])
	}
}

// MakeMoveCredentialEndpoint make the MoveCredential endpoint to change the priority of a credential of the current user.
func MakeMoveCredentialEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.MoveCredential(ctx, m["credentialID"], m["previousCredentialID"])
	}
}

// MakeGetAccountEndpoint makes the GetAccount endpoint to get connected user's info.
func MakeGetAccountEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetAccount(ctx)
	}
}

// MakeUpdateAccountEndpoint makes the UpdateAccount endpoint to update connected user's own info.
func MakeUpdateAccountEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.AccountRepresentation

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, errrorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = body.Validate(); err != nil {
			return nil, errrorhandler.CreateBadRequestError(err.Error())
		}

		return nil, component.UpdateAccount(ctx, body)
	}
}

// MakeDeleteAccountEndpoint makes the DeleteAccount endpoint to delete connected user.
func MakeDeleteAccountEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, component.DeleteAccount(ctx)
	}
}
