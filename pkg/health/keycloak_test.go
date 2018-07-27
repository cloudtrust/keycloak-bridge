package health_test

//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/health KeycloakClient

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	keycloak_client "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type keycloakReport struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

var hcUser = keycloak_client.UserRepresentation{
	Username:  Str("health.check"),
	FirstName: Str("Health"),
	LastName:  Str("Check"),
	Email:     Str("health.check@cloudtrust.ch"),
}

var vUser = keycloak_client.UserRepresentation{
	Username:  Str("version"),
	FirstName: Str("1.0"),
}

func TestNewKeycloakModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var enabled = true
	var userID = strconv.FormatUint(rand.Uint64(), 10)
	vUser.Id = Str(userID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	// Wrong version number.
	{
		var _, err = NewKeycloakModule(mockKeycloakClient, "1.0.0", enabled)
		assert.NotNil(t, err)
	}
	// Test realm already up to date.
	mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
	mockKeycloakClient.EXPECT().GetUser("__internal", userID).Return(vUser, nil).Times(1)
	NewKeycloakModule(mockKeycloakClient, "1.0", enabled)

	// Test realm does not exist.
	mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(nil, fmt.Errorf("fail")).Times(1)
	mockKeycloakClient.EXPECT().DeleteRealm("__internal").Return(nil).Times(1)
	mockKeycloakClient.EXPECT().CreateRealm(gomock.Any()).Return(nil).Times(1)
	mockKeycloakClient.EXPECT().CreateUser("__internal", gomock.Any()).Return(nil).Times(1)
	NewKeycloakModule(mockKeycloakClient, "1.0", enabled)
}

func TestKeycloakDisabled(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var (
		enabled  = false
		version  = "1.0"
		hcUserID = strconv.FormatUint(rand.Uint64(), 10)
		vUserID  = strconv.FormatUint(rand.Uint64(), 10)
	)
	hcUser.Id = Str(hcUserID)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	var m HealthChecker
	{
		mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)

		var err error
		m, err = NewKeycloakModule(mockKeycloakClient, version, enabled)
		assert.Nil(t, err)
	}

	var jsonReport, err = m.HealthCheck(context.Background(), "createuser")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []keycloakReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "keycloak", r.Name)
	assert.Equal(t, "Deactivated", r.Status)
	assert.Zero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestKeycloakCreateUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var (
		enabled  = true
		version  = "1.0"
		hcUserID = strconv.FormatUint(rand.Uint64(), 10)
		vUserID  = strconv.FormatUint(rand.Uint64(), 10)
	)
	hcUser.Id = Str(hcUserID)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	var m HealthChecker
	{
		mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)

		var err error
		m, err = NewKeycloakModule(mockKeycloakClient, version, enabled)
		assert.Nil(t, err)
	}

	mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
	mockKeycloakClient.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(1)
	mockKeycloakClient.EXPECT().CreateUser("__internal", gomock.Any()).Return(nil).Times(1)

	var jsonReport, err = m.HealthCheck(context.Background(), "createuser")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []keycloakReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "create user", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestKeycloakDeleteUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var (
		enabled  = true
		version  = "1.0"
		hcUserID = strconv.FormatUint(rand.Uint64(), 10)
		vUserID  = strconv.FormatUint(rand.Uint64(), 10)
	)
	hcUser.Id = Str(hcUserID)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	var m HealthChecker
	{
		mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)

		var err error
		m, err = NewKeycloakModule(mockKeycloakClient, version, enabled)
		assert.Nil(t, err)
	}

	mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
	mockKeycloakClient.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(1)

	var jsonReport, err = m.HealthCheck(context.Background(), "deleteuser")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []keycloakReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "delete user", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestKeycloakAllChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var (
		enabled  = true
		version  = "1.0"
		hcUserID = strconv.FormatUint(rand.Uint64(), 10)
		vUserID  = strconv.FormatUint(rand.Uint64(), 10)
	)
	hcUser.Id = Str(hcUserID)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	var m HealthChecker
	{
		mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)

		var err error
		m, err = NewKeycloakModule(mockKeycloakClient, version, enabled)
		assert.Nil(t, err)
	}

	mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(2)
	mockKeycloakClient.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(2)
	mockKeycloakClient.EXPECT().CreateUser("__internal", gomock.Any()).Return(nil).Times(1)

	var jsonReport, err = m.HealthCheck(context.Background(), "")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []keycloakReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "create user", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)

	r = report[1]
	assert.Equal(t, "delete user", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)
}
func TestKeycloakUnkownHealthCheck(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var (
		enabled         = true
		version         = "1.0"
		hcUserID        = strconv.FormatUint(rand.Uint64(), 10)
		vUserID         = strconv.FormatUint(rand.Uint64(), 10)
		healthCheckName = "unknown"
	)
	hcUser.Id = Str(hcUserID)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	var m HealthChecker
	{
		mockKeycloakClient.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
		mockKeycloakClient.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)

		var err error
		m, err = NewKeycloakModule(mockKeycloakClient, version, enabled)
		assert.Nil(t, err)
	}

	var f = func() {
		m.HealthCheck(context.Background(), healthCheckName)
	}
	assert.Panics(t, f)
}

func TestVersion(t *testing.T) {
	// Valid versions.
	{
		var versions = []string{"0.0", "1.1", "12.345"}
		var majorMinor = [][]int{{0, 0}, {1, 1}, {12, 345}}
		for i, version := range versions {
			var v, err = NewVersion(version)
			assert.Nil(t, err)
			assert.Equal(t, majorMinor[i][0], v.Major)
			assert.Equal(t, majorMinor[i][1], v.Minor)
			assert.Equal(t, version, v.String())
		}
	}
	// Invalid versions.
	{
		var versions = []string{"1", "1.0.0", "1..1", " 1.0", "1.a"}
		for _, version := range versions {
			var v, err = NewVersion(version)
			assert.NotNil(t, err)
			assert.Nil(t, v)
		}
	}
	// Comparison
	{
		var tests = []struct {
			v1       string
			v2       string
			superior bool
		}{
			{"1.0", "1.0", false},
			{"0.9", "1.0", false},
			{"1.9", "10.0", false},
			{"1.1", "1.0", true},
			{"2.0", "1.9", true},
		}
		for _, test := range tests {
			v1, err := NewVersion(test.v1)
			assert.Nil(t, err)
			v2, err := NewVersion(test.v2)
			assert.Nil(t, err)

			assert.Equal(t, test.superior, v1.Superior(v2))
		}
	}
}
