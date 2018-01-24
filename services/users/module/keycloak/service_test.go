package keycloak

import (
	"context"
	"errors"
	"testing"

	keycloak "github.com/cloudtrust/keycloak-client/client"
)

type mockKeycloakClient struct {
	users []keycloak.UserRepresentation
	fail  bool
}

var errFail = errors.New("generic failure")

func (m *mockKeycloakClient) GetRealms() ([]keycloak.RealmRepresentation, error) {
	return nil, nil
}

func (m *mockKeycloakClient) GetUsers(realm string) ([]keycloak.UserRepresentation, error) {
	if m.fail {
		return nil, errFail
	}
	return m.users, nil
}

func TestBasicService_GetUsers(t *testing.T) {
	var namesInit = [3]string{"john", "paul", "james"}
	var usersInit [3]keycloak.UserRepresentation
	for i, n := range namesInit {
		usersInit[i] = keycloak.UserRepresentation{
			Username: &n,
		}
	}
	var getUserService = NewBasicService(&mockKeycloakClient{
		usersInit[:],
		false,
	})

	names, err := getUserService.GetUsers(context.Background(), "master")
}

type mockService struct {
	names []string
}

func NewMockService(names []string) Service {
	return &mockService{names: names}
}

func (m *mockService) GetUsers(ctx context.Context, realm string) ([]string, error) {
	return m.names, nil
}
