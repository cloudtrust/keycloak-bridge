package health

import (
	"context"

	keycloak "github.com/cloudtrust/keycloak-client/client"
)

type KeycloakModule interface {
	HealthChecks(context.Context) []KeycloakHealthReport
}

type KeycloakHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

type Keycloak interface {
	GetRealms() ([]keycloak.RealmRepresentation, error)
	GetUsers(realm string) ([]keycloak.UserRepresentation, error)
}

type keycloakModule struct {
	keycloak Keycloak
}

// NewKeycloakModule returns the keycloak health module.
func NewKeycloakModule(keycloak Keycloak) KeycloakModule {
	return &keycloakModule{keycloak: keycloak}
}

// HealthChecks executes all health checks for Keycloak.
func (m *keycloakModule) HealthChecks(context.Context) []KeycloakHealthReport {
	var reports = []KeycloakHealthReport{}
	reports = append(reports, keycloakPingCheck(m.keycloak))
	return reports
}

func keycloakPingCheck(keycloak Keycloak) KeycloakHealthReport {
	// If keycloak is deactivated.
	if keycloak == nil {
		return KeycloakHealthReport{
			Name:     "ping",
			Duration: "N/A",
			Status:   Deactivated,
		}
	}
	/*
			var now = time.Now()
			var _, err = redis.Do("PING")
			var duration = time.Since(now)

			var status = OK
			var error = ""
			if err != nil {
				status = KO
				error = err.Error()
			}

		return KeycloakHealthReport{
			Name:     "ping",
			Duration: duration.String(),
			Status:   status,
			Error:    error,
		}*/
	return KeycloakHealthReport{
		Name:     "ping",
		Duration: "N/A",
		Status:   Deactivated,
	}
}
