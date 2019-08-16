package account

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/account"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	UpdatePassword        endpoint.Endpoint
	GetCredentials        endpoint.Endpoint
	GetCredentialTypes    endpoint.Endpoint
	UpdateLabelCredential endpoint.Endpoint
	DeleteCredential      endpoint.Endpoint
	MoveCredential        endpoint.Endpoint
}

// AccountComponent describes methods of the Account API
type AccountComponent interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
	GetCredentials(ctx context.Context) ([]api.CredentialRepresentation, error)
	GetCredentialTypes(ctx context.Context) ([]string, error)
	UpdateLabelCredential(ctx context.Context, credentialID string, label string) error
	DeleteCredential(ctx context.Context, credentialID string) error
	MoveCredential(ctx context.Context, credentialID string, previousCredentialID string) error
}

// MakeUpdatePasswordEndpoint makes the UpdatePassword endpoint to update connected user's own password.
func MakeUpdatePasswordEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body api.UpdatePasswordBody

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, http.CreateBadRequestError("Invalid body")
		}

		if err = body.Validate(); err != nil {
			return nil, http.CreateBadRequestError(err.Error())
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

// MakeGetCredentialTypesEndpoint make the GetCredentialTypes endpoint to retrieve the list of possible kind of credentials.
func MakeGetCredentialTypesEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetCredentialTypes(ctx)
	}
}

// MakeUpdateLabelCredentialEndpoint make the UpdateLabelCredential endpoint to set a new label for a credential.
func MakeUpdateLabelCredentialEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var body api.CredentialRepresentation

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, http.CreateBadRequestError("Invalid body")
		}

		if err = body.Validate(); err != nil {
			return nil, http.CreateBadRequestError(err.Error())
		}

		if body.UserLabel == nil {
			return nil, http.CreateBadRequestError("User label missing")
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
