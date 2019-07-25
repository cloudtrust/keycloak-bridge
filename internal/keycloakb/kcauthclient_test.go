package keycloakb

//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient

import (
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	accessToken = "TOKEN==="
	realm       = "realm"
	user        = "user"
	groupID     = "group.ID"
)

func testKeycloakAuthClient(t *testing.T, testable func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()
	var mockKeycloak = mock.NewKeycloakClient(mockCtrl)

	testable(t, mockKeycloak, NewKeycloakAuthClient(mockKeycloak, mockLogger))
}

func TestGetGroupNamesOfUserError(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		mockKeycloak.EXPECT().GetGroupsOfUser(accessToken, realm, user).Return([]kc.GroupRepresentation{}, errors.New("error")).Times(1)
		_, err := authClient.GetGroupNamesOfUser(accessToken, realm, user)
		assert.NotNil(t, err)
	})
}

func TestGetGroupNamesOfUserNilGroups(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		mockKeycloak.EXPECT().GetGroupsOfUser(accessToken, realm, user).Return(nil, nil).Times(1)
		res, err := authClient.GetGroupNamesOfUser(accessToken, realm, user)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(res))
	})
}

func TestGetGroupNamesOfUserSuccess(t *testing.T) {
	// GetGroupNamesOfUser: success with one valid groupname
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		var groupname = "name of group"
		var groups = []kc.GroupRepresentation{
			kc.GroupRepresentation{Name: nil},
			kc.GroupRepresentation{Name: &groupname},
		}
		mockKeycloak.EXPECT().GetGroupsOfUser(accessToken, realm, user).Return(groups, nil).Times(1)
		res, err := authClient.GetGroupNamesOfUser(accessToken, realm, user)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res))
	})
}

func TestGetGroupNameError(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{}, errors.New("error")).Times(1)
		_, err := authClient.GetGroupName(accessToken, realm, groupID)
		assert.NotNil(t, err)
	})
}

func TestGetGroupNameNilName(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{Name: nil}, nil).Times(1)
		res, err := authClient.GetGroupName(accessToken, realm, groupID)
		assert.Nil(t, err)
		assert.Equal(t, "", res)
	})
}

func TestGetGroupNameSuccess(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		var groupname = "the name"
		mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{Name: &groupname}, nil).Times(1)
		res, err := authClient.GetGroupName(accessToken, realm, groupID)
		assert.Nil(t, err)
		assert.Equal(t, groupname, res)
	})
}
