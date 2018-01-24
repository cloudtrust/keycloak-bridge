package keycloak

import (
	"context"
	"errors"
<<<<<<< HEAD:services/users/module/keycloak/service_test.go
	"io"
	"testing"

	keycloak "github.com/cloudtrust/keycloak-client/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
=======
	"testing"

	keycloak "github.com/cloudtrust/keycloak-client/client"
>>>>>>> origin/refactor_user:services/users/modules/keycloak/service_test.go
)

type mockKeycloakClient struct {
	users []keycloak.UserRepresentation
	fail  bool
}

<<<<<<< HEAD:services/users/module/keycloak/service_test.go
var ErrThatsNoGood = errors.New("That's too much man")
=======
var errFail = errors.New("generic failure")
>>>>>>> origin/refactor_user:services/users/modules/keycloak/service_test.go

func (m *mockKeycloakClient) GetRealms() ([]keycloak.RealmRepresentation, error) {
	return nil, nil
}

func (m *mockKeycloakClient) GetUsers(realm string) ([]keycloak.UserRepresentation, error) {
	if m.fail {
<<<<<<< HEAD:services/users/module/keycloak/service_test.go
		return nil, ErrThatsNoGood
=======
		return nil, errFail
>>>>>>> origin/refactor_user:services/users/modules/keycloak/service_test.go
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

<<<<<<< HEAD:services/users/module/keycloak/service_test.go
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
=======
	names, err := getUserService.GetUsers(context.Background(), "master")
>>>>>>> origin/refactor_user:services/users/modules/keycloak/service_test.go
}

type mockService struct {
	names []string
}

func NewMockService(names []string) Service {
	return &mockService{names: names}
}

<<<<<<< HEAD:services/users/module/keycloak/service_test.go
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
=======
func (m *mockService) GetUsers(ctx context.Context, realm string) ([]string, error) {
	return m.names, nil
>>>>>>> origin/refactor_user:services/users/modules/keycloak/service_test.go
}
