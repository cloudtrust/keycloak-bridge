package user

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	keycloak "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)

	var m = NewModule(mockKeycloakClient)

	var users = []string{"john", "jane", "doe"}
	mockKeycloakClient.EXPECT().GetUsers("realm").Return(getKeycloakUserRepresentation(users), nil).Times(1)
	var names, err = m.GetUsers(context.Background(), "realm")
	assert.Nil(t, err)
	assert.Equal(t, users, names)

	// Keycloak client error.
	mockKeycloakClient.EXPECT().GetUsers("realm").Return(nil, fmt.Errorf("fail")).Times(1)
	names, err = m.GetUsers(context.Background(), "realm")
	assert.NotNil(t, err)
	assert.Nil(t, names)
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
