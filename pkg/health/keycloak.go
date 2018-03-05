package health

//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=Keycloak=Keycloak,KeycloakModule=KeycloakModule github.com/cloudtrust/keycloak-bridge/pkg/health Keycloak,KeycloakModule

import (
	"context"
	"fmt"
	"strings"
	"time"

	keycloak_client "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

const (
	// testRealm is the name of the realm used for the health checks.
	testRealm = "__internal"
	// vuserName is the version of the test realm, stored as a user.
	vuserName = "version"
)

// KeycloakModule is the health check module for keycloak.
type KeycloakModule interface {
	HealthChecks(context.Context) []KeycloakReport
}

// KeycloakReport is the health report returned by the keycloak module.
type KeycloakReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Keycloak is the interface of the keycloak client.
type Keycloak interface {
	GetRealms() ([]keycloak_client.RealmRepresentation, error)
	CreateRealm(realmName keycloak_client.RealmRepresentation) error
	GetRealm(realmName string) (keycloak_client.RealmRepresentation, error)
	UpdateRealm(realmName string, realm keycloak_client.RealmRepresentation) error
	DeleteRealm(realmName string) error
	GetUsers(realmName string, paramKV ...string) ([]keycloak_client.UserRepresentation, error)
	CreateUser(realmName string, user keycloak_client.UserRepresentation) error
	CountUsers(realmName string) (int, error)
	GetUser(realmName, userID string) (keycloak_client.UserRepresentation, error)
	UpdateUser(realmName, userID string, user keycloak_client.UserRepresentation) error
	DeleteUser(realmName, userID string) error
}

type keycloakModule struct {
	keycloak Keycloak
}

// NewKeycloakModule returns the keycloak health module.
func NewKeycloakModule(keycloak Keycloak, version string) KeycloakModule {
	updateTestRealm(keycloak, version)
	return &keycloakModule{keycloak: keycloak}
}

// HealthChecks executes all health checks for Keycloak.
func (m *keycloakModule) HealthChecks(context.Context) []KeycloakReport {
	var reports = []KeycloakReport{}
	reports = append(reports, m.keycloakCreateUserCheck())
	reports = append(reports, m.keycloakDeleteUserCheck())
	return reports
}

// healthCheckUser is the user used for the health tests.
var healthCheckUser = keycloak_client.UserRepresentation{
	Username:  Str("health.check"),
	FirstName: Str("Health"),
	LastName:  Str("Check"),
	Email:     Str("health.check@cloudtrust.ch"),
}

func (m *keycloakModule) keycloakCreateUserCheck() KeycloakReport {
	var healthCheckName = "create user"

	var error string
	var s Status

	// Delete health check user if it exists.
	m.keycloakDeleteUserCheck()

	var now = time.Now()
	var err = m.keycloak.CreateUser(testRealm, healthCheckUser)
	var duration = time.Since(now)

	switch {
	case err != nil:
		error = fmt.Sprintf("could not create user: %v", err.Error())
		s = KO
	default:
		s = OK
	}

	return KeycloakReport{
		Name:     healthCheckName,
		Duration: duration.String(),
		Status:   s,
		Error:    error,
	}
}

func (m *keycloakModule) keycloakDeleteUserCheck() KeycloakReport {
	var healthCheckName = "delete user"

	var error string
	var s Status
	// Get user ID.
	var userID string
	{
		var users, err = m.keycloak.GetUsers(testRealm, "username", *healthCheckUser.Username)

		switch {
		case err != nil:
			error = fmt.Sprintf("could not get user: %v", err.Error())
			s = KO
		case len(users) == 0:
			error = fmt.Sprintf("could not find user to delete")
			s = KO
		case users[0].Id == nil:
			error = fmt.Sprintf("user id should not be nil")
			s = KO
		default:
			userID = *users[0].Id
		}
	}
	if userID == "" {
		return KeycloakReport{
			Name:     healthCheckName,
			Duration: "N/A",
			Status:   s,
			Error:    error,
		}
	}

	var now = time.Now()
	var err = m.keycloak.DeleteUser(testRealm, userID)
	var duration = time.Since(now)

	switch {
	case err != nil:
		error = fmt.Sprintf("could not delete user: %v", err.Error())
		s = KO
	default:
		s = OK
	}

	return KeycloakReport{
		Name:     healthCheckName,
		Duration: duration.String(),
		Status:   s,
		Error:    error,
	}
}

func updateTestRealm(keycloak Keycloak, version string) error {
	// Check the test realm version. If the realm does not exists, we receive an error.
	var vuser, err = keycloak.GetUser(testRealm, vuserName)
	if err != nil || vuser.FirstName == nil || *vuser.FirstName != version {
		// The test realm does not exits or is not up to date, so we create/update it.
		var err = createTestRealm(keycloak, version)
		if err != nil {
			keycloak.DeleteRealm(testRealm)
			return errors.Wrap(err, "could not create test realm")
		}
		err = createTestUsers(keycloak, version)
		if err != nil {
			keycloak.DeleteRealm(testRealm)
			return errors.Wrap(err, "could not create test users")
		}
	}
	return nil
}

func createTestRealm(keycloak Keycloak, version string) error {
	// Delete old realm.
	keycloak.DeleteRealm(testRealm)

	// Create new realm.
	var realm = testRealm
	return keycloak.CreateRealm(keycloak_client.RealmRepresentation{
		Realm: &realm,
	})
}

var tstUsers = []struct {
	firstname string
	lastname  string
}{
	{"John", "Doe"},
}

func createTestUsers(keycloak Keycloak, version string) error {
	for _, u := range tstUsers {
		var username = strings.ToLower(u.firstname + "." + u.lastname)
		var email = username + "@cloudtrust.ch"
		var err = keycloak.CreateUser(testRealm, keycloak_client.UserRepresentation{
			Username:  &username,
			FirstName: &u.firstname,
			LastName:  &u.lastname,
			Email:     &email,
		})
		if err != nil {
			return errors.Wrap(err, "could not create test users")
		}
	}

	// The version of the test realm is stored in a user.
	var username = vuserName
	var err = keycloak.CreateUser(testRealm, keycloak_client.UserRepresentation{
		Username:  &username,
		FirstName: &version,
	})
	if err != nil {
		return errors.Wrap(err, "could not create version user")
	}
	return nil
}

func Str(s string) *string {
	return &s
}
