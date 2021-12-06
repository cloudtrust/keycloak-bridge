package keycloakb

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
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
		_, err := authClient.GetGroupNamesOfUser(context.TODO(), accessToken, realm, user)
		assert.NotNil(t, err)
	})
}

func TestGetGroupNamesOfUserNilGroups(t *testing.T) {
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		mockKeycloak.EXPECT().GetGroupsOfUser(accessToken, realm, user).Return(nil, nil).Times(1)
		res, err := authClient.GetGroupNamesOfUser(context.TODO(), accessToken, realm, user)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(res))
	})
}

func TestGetGroupNamesOfUserSuccess(t *testing.T) {
	// GetGroupNamesOfUser: success with one valid groupname
	testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
		var groupname = "name of group"
		var groups = []kc.GroupRepresentation{
			{Name: nil},
			{Name: &groupname},
		}
		mockKeycloak.EXPECT().GetGroupsOfUser(accessToken, realm, user).Return(groups, nil).Times(1)
		res, err := authClient.GetGroupNamesOfUser(context.TODO(), accessToken, realm, user)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res))
	})
}

func TestGetGroupName(t *testing.T) {
	t.Run("Error", func(t *testing.T) {
		testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
			mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{}, errors.New("error")).Times(1)
			_, err := authClient.GetGroupName(context.TODO(), accessToken, realm, groupID)
			assert.NotNil(t, err)
		})
	})
	t.Run("Nil name", func(t *testing.T) {
		testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
			mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{Name: nil}, nil).Times(1)
			res, err := authClient.GetGroupName(context.TODO(), accessToken, realm, groupID)
			assert.Nil(t, err)
			assert.Equal(t, "", res)
		})
	})
	t.Run("Success", func(t *testing.T) {
		testKeycloakAuthClient(t, func(t *testing.T, mockKeycloak *mock.KeycloakClient, authClient security.KeycloakClient) {
			var groupname = "the name"
			mockKeycloak.EXPECT().GetGroup(accessToken, realm, groupID).Return(kc.GroupRepresentation{Name: &groupname}, nil).Times(1)
			res, err := authClient.GetGroupName(context.TODO(), accessToken, realm, groupID)
			assert.Nil(t, err)
			assert.Equal(t, groupname, res)
		})
	})
}

func TestGetID(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockKeycloak = mock.NewKeycloakClient(mockCtrl)
	var idRetriever = NewRealmIDRetriever(mockKeycloak)

	t.Run("Error", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, errors.New("error"))
		_, err := idRetriever.GetID(accessToken, realm)
		assert.NotNil(t, err)
	})
	t.Run("Nil name", func(t *testing.T) {
		mockKeycloak.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{}, nil)
		id, err := idRetriever.GetID(accessToken, realm)
		assert.Nil(t, err)
		assert.Equal(t, "", id)
	})
	t.Run("Success", func(t *testing.T) {
		var id = "the-realm-identifier"
		mockKeycloak.EXPECT().GetRealm(accessToken, realm).Return(kc.RealmRepresentation{ID: &id}, nil)
		res, err := idRetriever.GetID(accessToken, realm)
		assert.Nil(t, err)
		assert.Equal(t, id, res)
	})
}
