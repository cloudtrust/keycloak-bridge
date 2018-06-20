package health_test

//go:generate mockgen -destination=./mock/keycloakclient.go -package=mock -mock_names=Keycloak=Keycloak github.com/cloudtrust/keycloak-bridge/pkg/health Keycloak

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	keycloak_client "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

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
	var mockKeycloak = mock.NewKeycloak(mockCtrl)

	rand.Seed(time.Now().UnixNano())
	var userID = strconv.FormatUint(rand.Uint64(), 10)
	vUser.Id = Str(userID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	// Wrong version number.
	{
		var _, err = NewKeycloakModule(mockKeycloak, "1.0.0")
		assert.NotNil(t, err)
	}
	// Test realm already up to date.
	mockKeycloak.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
	mockKeycloak.EXPECT().GetUser("__internal", userID).Return(vUser, nil).Times(1)
	NewKeycloakModule(mockKeycloak, "1.0")

	// Test realm does not exist.
	mockKeycloak.EXPECT().GetUsers("__internal", "username", "version").Return(nil, fmt.Errorf("fail")).Times(1)
	mockKeycloak.EXPECT().DeleteRealm("__internal").Return(nil).Times(1)
	mockKeycloak.EXPECT().CreateRealm(gomock.Any()).Return(nil).Times(1)
	mockKeycloak.EXPECT().CreateUser("__internal", gomock.Any()).Return(nil).Times(1)
	NewKeycloakModule(mockKeycloak, "1.0")
}

func TestKeycloakHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloak = mock.NewKeycloak(mockCtrl)

	rand.Seed(time.Now().UnixNano())
	var hcUserID = strconv.FormatUint(rand.Uint64(), 10)
	hcUser.Id = Str(hcUserID)
	var vUserID = strconv.FormatUint(rand.Uint64(), 10)
	vUser.Id = Str(vUserID)
	var users = []keycloak_client.UserRepresentation{hcUser, vUser}

	mockKeycloak.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
	mockKeycloak.EXPECT().GetUser("__internal", vUserID).Return(vUser, nil).Times(1)
	var m, err = NewKeycloakModule(mockKeycloak, "1.0")
	assert.Nil(t, err)

	// HealthChecks
	{
		// keycloakCreateUserCheck
		mockKeycloak.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
		mockKeycloak.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(1)
		mockKeycloak.EXPECT().CreateUser("__internal", gomock.Any()).Return(nil).Times(1)
		// keycloakDeleteUserCheck
		mockKeycloak.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
		mockKeycloak.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(1)
		var reports = m.HealthChecks(context.Background())
		assert.Equal(t, 2, len(reports))
		// Create user report
		{
			var report = reports[0]
			assert.Equal(t, "create user", report.Name)
			assert.NotZero(t, report.Duration)
			assert.Equal(t, common.OK, report.Status)
			assert.Zero(t, report.Error)
		}
		// Delete user report
		{
			var report = reports[1]
			assert.Equal(t, "delete user", report.Name)
			assert.NotZero(t, report.Duration)
			assert.Equal(t, common.OK, report.Status)
			assert.Zero(t, report.Error)
		}
	}

	// Keycloak fail.
	{
		// keycloakCreateUserCheck
		mockKeycloak.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
		mockKeycloak.EXPECT().DeleteUser("__internal", hcUserID).Return(nil).Times(1)
		mockKeycloak.EXPECT().CreateUser("__internal", gomock.Any()).Return(fmt.Errorf("fail")).Times(1)
		// keycloakDeleteUserCheck
		mockKeycloak.EXPECT().GetUsers("__internal", "username", "health.check").Return(users, nil).Times(1)
		mockKeycloak.EXPECT().DeleteUser("__internal", hcUserID).Return(fmt.Errorf("fail")).Times(1)
		var reports = m.HealthChecks(context.Background())
		assert.Equal(t, 2, len(reports))
		// Create user report
		{
			var report = reports[0]
			assert.Equal(t, "create user", report.Name)
			assert.NotZero(t, report.Duration)
			assert.Equal(t, common.KO, report.Status)
			assert.NotZero(t, report.Error)
		}
		// Delete user report
		{
			var report = reports[1]
			assert.Equal(t, "delete user", report.Name)
			assert.NotZero(t, report.Duration)
			assert.Equal(t, common.KO, report.Status)
			assert.NotZero(t, report.Error)
		}
	}
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
