package health_test

import (
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

	// Test realm already up to date.
	mockKeycloak.EXPECT().GetUsers("__internal", "username", "version").Return(users, nil).Times(1)
	mockKeycloak.EXPECT().GetUser("__internal", userID).Return(vUser, nil).Times(1)
	NewKeycloakModule(mockKeycloak, "1.0")
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
