package account

import (
	"context"
	"net/http"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	commonhttp "github.com/cloudtrust/common-service/http"
)

// KeycloakClient interface exposes methods we need to call to send requests to Keycloak API
type KeycloakClient interface {
	UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword string) (string, error)
}

// Component interface exposes methods used by the bridge API
type Component interface {
	UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error
}

// Component is the management component.
type component struct {
	keycloakClient KeycloakClient
	eventDBModule  database.EventsDBModule
}

// NewComponent returns the self-service component.
func NewComponent(keycloakClient KeycloakClient, eventDBModule database.EventsDBModule) Component {
	return &component{
		keycloakClient: keycloakClient,
		eventDBModule:  eventDBModule,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) error {
	return c.eventDBModule.ReportEvent(ctx, apiCall, "self-service", values...)
}

func (c *component) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var realm = ctx.Value(cs.CtContextRealm).(string)
	var userID = ctx.Value(cs.CtContextUserID).(string)
	var username = ctx.Value(cs.CtContextUsername).(string)

	if currentPassword == newPassword || newPassword != confirmPassword {
		return commonhttp.Error{
			Status: http.StatusBadRequest,
		}
	}

	_, err := c.keycloakClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)

	var updateError error
	switch err.Error() {
	case "invalidPasswordExistingMessage":
		updateError = commonhttp.Error{
			Status:  http.StatusBadRequest,
			Message: err.Error()}
	default:
		updateError = err
	}

	//store the API call into the DB
	_ = c.reportEvent(ctx, "PASSWORD_RESET", "realm_name", realm, "user_id", userID, "username", username)

	return updateError
}
