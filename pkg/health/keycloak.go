package health

import (
	"context"
	"fmt"
	"strings"
	"time"

	keycloak_client "github.com/cloudtrust/keycloak-client"
)

const (
	// testRealm is the name of the realm used for the health checks.
	testRealm = "__internal"
	// vuserName is the version of the test realm, stored as a user.
	vuserName = "version"
)

// healthCheckUser is the user used for the health tests.
var healthCheckUser = keycloak_client.UserRepresentation{
	Username:  str("health.check"),
	FirstName: str("Health"),
	LastName:  str("Check"),
	Email:     str("health.check@cloudtrust.ch"),
}

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
func (m *keycloakModule) HealthChecks(context.Context) []KeycloakHealthReport {
	var reports = []KeycloakHealthReport{}
	reports = append(reports, keycloakCreateUserCheck(m.keycloak))
	return reports
}

func keycloakCreateUserCheck(keycloak Keycloak) KeycloakHealthReport {
	var report = KeycloakHealthReport{
		Name:     "create user",
		Duration: "N/A",
		Status:   KO,
	}
	// Delete health check user if it exists.
	var users []keycloak_client.UserRepresentation
	{
		var err error
		users, err = keycloak.GetUsers(testRealm, "username", *healthCheckUser.Username)
		if err != nil {
			report.Error = "could not get user: " + err.Error()
			return report
		}
		if len(users) != 0 {
			if users[0].Id == nil {
				report.Error = "cuser id should not be nil: " + err.Error()
				return report
			}
			var err = keycloak.DeleteUser(testRealm, *users[0].Id)
			if err != nil {
				report.Error = "could not delete user: " + err.Error()
				return report
			}
		}
	}

	var now = time.Now()
	var err = keycloak.CreateUser(testRealm, healthCheckUser)
	if err != nil {
		report.Error = "could not create user: " + err.Error()
		return report
	}
	var duration = time.Since(now)

	report.Status = OK
	report.Duration = duration.String()
	return report
}

func updateTestRealm(keycloak Keycloak, version string) error {
	// Check the test realm version. If the realm does not exists, we receive an error.
	var vuser, err = keycloak.GetUser(testRealm, vuserName)
	if err != nil || vuser.FirstName == nil || *vuser.FirstName != version {
		// The test realm does not exits or is not up to date, so we create/update it.
		var err = createTestRealm(keycloak, version)
		if err != nil {
			keycloak.DeleteRealm(testRealm)
			return fmt.Errorf("could not create test realm: %v", err)
		}
		err = createTestUsers(keycloak, version)
		if err != nil {
			keycloak.DeleteRealm(testRealm)
			return fmt.Errorf("could not create test users: %v", err)
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
	{"Tracey", "Briggs"},
	{"Karen", "Sutton"},
	{"Cesar", "Mathis"},
	{"Ryan", "Kennedy"},
	{"Kent", "Phillips"},
	{"Loretta", "Curtis"},
	{"Derrick", "Cox"},
	{"Greg", "Wilkins"},
	{"Andy", "Reynolds"},
	{"Toni", "Meyer"},
	{"Joyce", "Sullivan"},
	{"Johanna", "Fitzgerald"},
	{"Judith", "Barnett"},
	{"Joanne", "Ward"},
	{"Bethany", "Johnson"},
	{"Maria", "Murphy"},
	{"Mattie", "Quinn"},
	{"Erick", "Robbins"},
	{"Beulah", "Greer"},
	{"Patty", "Wong"},
	{"Gayle", "Garrett"},
	{"Stewart", "Floyd"},
	{"Wilbur", "Schneider"},
	{"Diana", "Logan"},
	{"Eduardo", "Mitchell"},
	{"Lela", "Hernandez"},
	{"Homer", "Miles"},
	{"Audrey", "Park"},
	{"Rebecca", "Fuller"},
	{"Jeremiah", "Andrews"},
	{"Cedric", "Reyes"},
	{"Lee", "Griffin"},
	{"Ebony", "Knight"},
	{"Gilbert", "Franklin"},
	{"Jessie", "Norman"},
	{"Cary", "Wells"},
	{"Arlene", "James"},
	{"Jerry", "Chavez"},
	{"Marco", "Weber"},
	{"Celia", "Guerrero"},
	{"Faye", "Massey"},
	{"Jorge", "Mccarthy"},
	{"Jennifer", "Colon"},
	{"Angel", "Jordan"},
	{"Bennie", "Hubbard"},
	{"Terrance", "Norris"},
	{"May", "Sharp"},
	{"Glenda", "Hogan"},
	{"Lucia", "Nelson"},
	{"Kathleen", "Sanchez"},
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
			return fmt.Errorf("could not create test users: %v", err)
		}
	}

	// The version of the test realm is stroed in a user.
	var username = vuserName
	var err = keycloak.CreateUser(testRealm, keycloak_client.UserRepresentation{
		Username:  &username,
		FirstName: &version,
	})
	if err != nil {
		return fmt.Errorf("could not create version user: %v", err)
	}
	return nil
}

func str(s string) *string {
	return &s
}
