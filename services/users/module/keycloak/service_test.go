package keycloak

import (
	"context"
	"errors"
	"io"
	"testing"

	keycloak "github.com/cloudtrust/keycloak-client/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeycloakClient struct {
	users []keycloak.UserRepresentation
	fail  bool
}

var ErrThatsNoGood = errors.New("That's too much man")

func (m *mockKeycloakClient) GetRealms() ([]keycloak.RealmRepresentation, error) {
	return nil, nil
}

func (m *mockKeycloakClient) GetUsers(realm string) ([]keycloak.UserRepresentation, error) {
	if m.fail {
		return nil, ErrThatsNoGood
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

	resultc, errc := getUserService.GetUsers(context.Background(), "master")
	var names [3]string
loop:
	for i := 0; i < 4; i++ {
		select {
		case name := <-resultc:
			require.Condition(t,
				func() (success bool) {
					success = i < 3
					return success
				},
				"should return only 3 names!",
			)
			names[i] = name
		case err := <-errc:
			assert.Equal(t, 3, i)
			assert.Equal(t, err, io.EOF)
			break loop
		}
	}
}

type mockService struct {
	names []string
}

func NewMockService(names []string) Service {
	return &mockService{names: names}
}

func (m *mockService) GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	var resultc = make(chan string)
	var errc = make(chan error)
	go func() {
		for _, n := range m.names {
			resultc <- n
		}
		errc <- io.EOF
	}()
	return resultc, errc
}
