package health

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	keycloak_client "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

const (
	// testRealm is the name of the realm used for the health checks.
	testRealm = "__internal"
	// vuserName is the version of the test realm, stored as a user.
	vuserName = "version"
)

// NewKeycloakModule update the test realm and returns the keycloak health module.
func NewKeycloakModule(keycloak KeycloakClient, version string, enabled bool) (*KeycloakModule, error) {
	var m = &KeycloakModule{keycloak: keycloak, enabled: enabled}
	var v, err = NewVersion(version)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid version number: %s", version)
	}
	return m, m.updateTestRealm(v)
}

// KeycloakModule is the health check module for influx.
type KeycloakModule struct {
	keycloak KeycloakClient
	enabled  bool
}

// KeycloakClient is the interface of the keycloak client.
type KeycloakClient interface {
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

type keycloakReport struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

// HealthCheck executes the desired keycloak health check.
func (m *KeycloakModule) HealthCheck(_ context.Context, name string) (json.RawMessage, error) {
	if !m.enabled {
		return json.MarshalIndent([]keycloakReport{{Name: "keycloak", Status: common.Deactivated.String()}}, "", "  ")
	}

	var reports []keycloakReport
	switch name {
	case "":
		reports = append(reports, m.keycloakCreateUserCheck())
		reports = append(reports, m.keycloakDeleteUserCheck())
	case "createuser":
		reports = append(reports, m.keycloakCreateUserCheck())
	case "deleteuser":
		reports = append(reports, m.keycloakDeleteUserCheck())
	default:
		// Should not happen: there is a middleware validating the inputs name.
		panic(fmt.Sprintf("Unknown keycloak health check name: %v", name))
	}

	return json.MarshalIndent(reports, "", "  ")
}

// healthCheckUser is the user used for the health tests.
var healthCheckUser = keycloak_client.UserRepresentation{
	Username:  Str("health.check"),
	FirstName: Str("Health"),
	LastName:  Str("Check"),
	Email:     Str("health.check@cloudtrust.ch"),
}

func (m *KeycloakModule) keycloakCreateUserCheck() keycloakReport {
	var name = "create user"
	var status = common.OK

	// Delete health check user if it exists.
	m.keycloakDeleteUserCheck()

	var now = time.Now()
	var err = m.keycloak.CreateUser(testRealm, healthCheckUser)
	var duration = time.Since(now)

	switch {
	case err != nil:
		err = errors.Wrap(err, "could not create user")
		status = common.KO
	default:
		status = common.OK
	}

	return keycloakReport{
		Name:     name,
		Duration: duration.String(),
		Status:   status.String(),
		Error:    str(err),
	}
}

func (m *KeycloakModule) keycloakDeleteUserCheck() keycloakReport {
	var name = "delete user"
	var status = common.OK

	// Get user ID.
	var userID string
	{
		var err error
		userID, err = m.getUserID(testRealm, *healthCheckUser.Username)
		if err != nil {
			return keycloakReport{
				Name:   name,
				Status: common.KO.String(),
				Error:  str(err),
			}
		}
	}

	var now = time.Now()
	var err = m.keycloak.DeleteUser(testRealm, userID)
	var duration = time.Since(now)

	switch {
	case err != nil:
		err = errors.Wrap(err, "could not delete user")
		status = common.KO
	default:
		status = common.OK
	}

	return keycloakReport{
		Name:     name,
		Duration: duration.String(),
		Status:   status.String(),
		Error:    str(err),
	}
}

func (m *KeycloakModule) getUserID(realm, username string) (string, error) {
	var users, err = m.keycloak.GetUsers(realm, "username", username)
	if err != nil {
		return "", fmt.Errorf("could not get user: %v", err.Error())
	}

	for _, user := range users {
		if user.Username != nil && *user.Username == username && user.Id != nil {
			return *user.Id, nil
		}
	}
	return "", fmt.Errorf("coult not get userID for '%v' in realm '%v'", username, realm)
}

func (m *KeycloakModule) updateTestRealm(v *Version) error {

	// Check the test realm version. If the realm does not exists, we receive an error.
	var vuserID string
	{
		var err error
		vuserID, err = m.getUserID(testRealm, vuserName)
		if err != nil {
			return m.createTestRealm(v)
		}
	}

	var vuser, err = m.keycloak.GetUser(testRealm, vuserID)
	if err != nil {
		return err
	}
	if vuser.FirstName != nil {
		// Check it the test realm is up to date.
		var currentVersion, err = NewVersion(*vuser.FirstName)
		if err != nil {
			return m.createTestRealm(v)
		}

		// Update realm
		if v.Superior(currentVersion) {
			return m.createTestRealm(v)
		}
	}

	return nil
}

func (m *KeycloakModule) createTestRealm(v *Version) error {
	// Delete old realm.
	m.keycloak.DeleteRealm(testRealm)

	// Create new realm.
	{
		var realm = testRealm
		var err = m.keycloak.CreateRealm(keycloak_client.RealmRepresentation{Realm: &realm})
		if err != nil {
			return errors.Wrap(err, "could not create test realm")
		}
	}
	// Create version user (the test realm is versionned, and the current version is stored as the Firstname of vuser).
	{
		var username = vuserName
		var err = m.keycloak.CreateUser(testRealm, keycloak_client.UserRepresentation{
			Username:  &username,
			FirstName: Str(v.String()),
		})
		if err != nil {
			return errors.Wrap(err, "could not create version user")
		}
	}
	return nil
}

// Str returns a pointer to str.
func Str(str string) *string {
	return &str
}

// Version contains the version of the component. The format is major.minor.
type Version struct {
	Major int
	Minor int
}

// NewVersion returns a Version representaion of the string v.
func NewVersion(v string) (*Version, error) {
	var r, err = regexp.Compile("^([0-9]+)\\.([0-9]+)$")
	if err != nil {
		return nil, errors.Wrap(err, "could not compile regexp to check version")
	}

	var matches = r.FindStringSubmatch(v)
	if len(matches) != 3 {
		return nil, fmt.Errorf("version should be major.minor: '%s'", v)
	}
	var major, _ = strconv.Atoi(matches[1])
	var minor, _ = strconv.Atoi(matches[2])

	return &Version{Major: major, Minor: minor}, nil
}

// Superior returns true if the version v is superior to v2, false otherwise.
func (v *Version) Superior(v2 *Version) bool {
	switch {
	case v.Major > v2.Major:
		return true
	case v.Major == v2.Major && v.Minor > v2.Minor:
		return true
	default:
		return false
	}
}

func (v *Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// str return the string error that will be in the health report
func str(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
