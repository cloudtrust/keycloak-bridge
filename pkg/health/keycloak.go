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

// KeycloakModule is the health check module for keycloak.
type KeycloakModule interface {
	HealthChecks(context.Context) []KeycloakReport
}

// KeycloakReport is the health report returned by the keycloak module.
type KeycloakReport struct {
	Name     string
	Duration time.Duration
	Status   common.Status
	Error    error
}

func (i *KeycloakReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Name     string `json:"name"`
		Duration string `json:"duration"`
		Status   string `json:"status"`
		Error    string `json:"error"`
	}{
		Name:     i.Name,
		Duration: i.Duration.String(),
		Status:   i.Status.String(),
		Error:    err(i.Error),
	})
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

// NewKeycloakModule update the test realm and returns the keycloak health module.
func NewKeycloakModule(keycloak Keycloak, version string) (KeycloakModule, error) {
	var m = &keycloakModule{keycloak: keycloak}
	var v, err = NewVersion(version)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid version number: %s", version)
	}
	return m, m.updateTestRealm(v)
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

	var s common.Status

	// Delete health check user if it exists.
	m.keycloakDeleteUserCheck()

	var now = time.Now()
	var err = m.keycloak.CreateUser(testRealm, healthCheckUser)
	var duration = time.Since(now)

	switch {
	case err != nil:
		err = errors.Wrap(err, "could not create user")
		s = common.KO
	default:
		s = common.OK
	}

	return KeycloakReport{
		Name:     healthCheckName,
		Duration: duration,
		Status:   s,
		Error:    err,
	}
}

func (m *keycloakModule) keycloakDeleteUserCheck() KeycloakReport {
	var healthCheckName = "delete user"

	// Get user ID.
	var userID string
	{
		var err error
		userID, err = m.getUserID(testRealm, *healthCheckUser.Username)
		if err != nil {
			return KeycloakReport{
				Name:   healthCheckName,
				Status: common.KO,
				Error:  err,
			}
		}
	}

	var now = time.Now()
	var err = m.keycloak.DeleteUser(testRealm, userID)
	var duration = time.Since(now)

	var s common.Status
	switch {
	case err != nil:
		err = errors.Wrap(err, "could not delete user")
		s = common.KO
	default:
		s = common.OK
	}

	return KeycloakReport{
		Name:     healthCheckName,
		Duration: duration,
		Status:   s,
		Error:    err,
	}
}

func (m *keycloakModule) getUserID(realm, username string) (string, error) {
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

func (m *keycloakModule) updateTestRealm(v *Version) error {

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

func (m *keycloakModule) createTestRealm(v *Version) error {
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

// err return the string error that will be in the health report
func err(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
