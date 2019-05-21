package account

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	UpdatePassword endpoint.Endpoint
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
