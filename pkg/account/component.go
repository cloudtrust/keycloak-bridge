package account

import (
	"context"
	"net/http"

	kcevent "github.com/cloudtrust/keycloak-bridge/internal/event"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
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
	eventDBModule  event.EventsDBModule
}

func reportEvent(ctx context.Context, eventDb event.EventsDBModule, apiCall string, values ...string) error {
	return kcevent.ReportEvent(ctx, eventDb, apiCall, "self-service", values...)
}

// NewComponent returns the self-service component.
func NewComponent(keycloakClient KeycloakClient, eventDBModule event.EventsDBModule) Component {
	return &component{
		keycloakClient: keycloakClient,
		eventDBModule:  eventDBModule,
	}
}

func (c *component) UpdatePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) error {
	var accessToken = ctx.Value("access_token").(string)
	var realm = ctx.Value("realm").(string)
	var userID = ctx.Value("userId").(string)
	var username = ctx.Value("username").(string)

	if currentPassword == newPassword || newPassword != confirmPassword {
		return keycloakb.HTTPError{
			Status: http.StatusBadRequest,
		}
	}

	_, err := c.keycloakClient.UpdatePassword(accessToken, realm, currentPassword, newPassword, confirmPassword)

	//store the API call into the DB
	_ = reportEvent(ctx, c.eventDBModule, "PASSWORD_RESET", "realm_name", realm, "user_id", userID, "username", username)

	return err
}
