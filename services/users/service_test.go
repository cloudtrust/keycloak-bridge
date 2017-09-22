package users

import (
	"testing"
	keycloak "github.com/elca-kairos-py/keycloak-client/client"
	"errors"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/assert"
	"io"
	"context"
)

type mockKeycloakClient struct {
	users []keycloak.UserRepresentation
	fail bool
}

var ThatsNoGood = errors.New("That's too much man!")

func (m *mockKeycloakClient)GetRealms() ([]map[string]interface{}, error) {
	return nil,nil
}

func (m *mockKeycloakClient)GetUsers(realm string) ([]keycloak.UserRepresentation, error){
	if m.fail {
		return nil, ThatsNoGood
	}
	return m.users,nil
}




func TestBasicService_GetUsers(t *testing.T) {
	var namesInit = [3]string{"john", "paul", "james"}
	var usersInit [3]keycloak.UserRepresentation
	for i,n := range namesInit {
		usersInit[i] = keycloak.UserRepresentation{
			Username:&n,
		}
	}
	var getUserService = NewBasicService(&mockKeycloakClient{
		usersInit[:],
		false,
		})

	resultc, errc := getUserService.GetUsers(context.Background(), "master")
	var names [3]string
	loop:for i:=0; i < 4; i++ {
		select {
		case name := <-resultc:
			require.Condition(t,
				func() (success bool) {
					success = i<3
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