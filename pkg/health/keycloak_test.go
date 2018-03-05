package health_test

import (
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	keycloak_client "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
)

func TestNewKeycloakModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloak = mock.NewKeycloak(mockCtrl)

	// Get version.
	{
		var users = keycloak_client.UserRepresentation{
			Username:  Str("health.check"),
			FirstName: Str("Health"),
			LastName:  Str("Check"),
			Email:     Str("health.check@cloudtrust.ch"),
		}
		mockKeycloak.EXPECT().GetUser("__internal", "version").Return(users, nil).Times(1)

		NewKeycloakModule(mockKeycloak, "1.0")
	}
}
