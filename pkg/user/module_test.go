package user

import (
	"context"
	"fmt"
	"testing"

	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestModule(t *testing.T) {
	var users = []string{"john", "jane", "doe"}
	var mockKeycloakClient = &mockKeycloakClient{
		fail:  false,
		users: getKeycloakUserRepresentation(users),
	}

	var m = NewModule(mockKeycloakClient)
	var names, err = m.GetUsers(context.Background(), "realm")
	assert.Nil(t, err)
	assert.Equal(t, users, names)
}

func getKeycloakUserRepresentation(names []string) []keycloak.UserRepresentation {
	var users []keycloak.UserRepresentation
	for _, name := range names {
		var n = name
		users = append(users, keycloak.UserRepresentation{
			Username: &n,
		})
	}
	return users
}

// Mock keycloak client.
type mockKeycloakClient struct {
	called bool
	fail   bool
	users  []keycloak.UserRepresentation
}

func (c *mockKeycloakClient) GetUsers(realm string) ([]keycloak.UserRepresentation, error) {
	if c.fail {
		return nil, fmt.Errorf("fail")
	}
	return c.users, nil
}

// Mock Module
type mockModule struct {
	called bool
	fail   bool
	users  []string
}

func (m *mockModule) GetUsers(ctx context.Context, realm string) ([]string, error) {
	m.called = true
	if m.fail {
		return nil, fmt.Errorf("fail")
	}
	return m.users, nil
}
