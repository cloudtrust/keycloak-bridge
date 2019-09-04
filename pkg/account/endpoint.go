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
	UpdatePassword endpoint.Endpoint
	GetAccount     endpoint.Endpoint
	UpdateAccount  endpoint.Endpoint
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
	GetAccount(ctx context.Context) (api.AccountRepresentation, error)
	UpdateAccount(ctx context.Context, account api.AccountRepresentation) error
}

// MakeUpdatePasswordEndpoint makes the UpdatePassword endpoint to update connected user's own password.
func MakeUpdatePasswordEndpoint(component AccountComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var body UpdatePasswordBody

		err := json.Unmarshal([]byte(m["body"]), &body)
		if err != nil {
			return nil, http.CreateBadRequestError("Invalid body")
		}

		return nil, component.UpdatePassword(ctx, body.CurrentPassword, body.NewPassword, body.ConfirmPassword)
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
			return nil, http.CreateBadRequestError("Invalid body")
		}

		if err = body.Validate(); err != nil {
			return nil, http.CreateBadRequestError(err.Error())
		}

		return nil, component.UpdateAccount(ctx, body)
	}
}
