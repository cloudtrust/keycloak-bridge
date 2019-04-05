package management

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=ManagementComponent=ManagementComponent github.com/cloudtrust/keycloak-bridge/pkg/management ManagementComponent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetRealmEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm

	mockManagementComponent.EXPECT().GetRealm(ctx, realm).Return(api.RealmRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientEndpoint(mockManagementComponent)

	var realm = "master"
	var clientID = "1234-4567-7895"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["clientID"] = clientID

	mockManagementComponent.EXPECT().GetClient(ctx, realm, clientID).Return(api.ClientRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestGetClientsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientsEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm

	mockManagementComponent.EXPECT().GetClients(ctx, realm).Return([]api.ClientRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestCreateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateUserEndpoint(mockManagementComponent)

	var realm = "master"
	var location = "https://location.url/auth/admin/master/users/123456"
	var ctx = context.Background()

	// No error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		req["body"] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, api.UserRepresentation{}).Return(location, nil).Times(1)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	}

	// Error - Cannot unmarshall
	{
		var req = make(map[string]string)
		req["body"] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}

	// Error - Keycloak client error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		req["body"] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, gomock.Any()).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}
}

func TestDeleteUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().DeleteUser(ctx, realm, userID).Return(nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().GetUser(ctx, realm, userID).Return(api.UserRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestUpdateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		req["body"] = string(userJSON)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// Error - JSON unmarshalling error
	{
		var realm = "master"
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["body"] = string("userJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestGetUsersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUsersEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var group = "Support"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["group"] = "Support"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, group, "group", req["group"]).Return([]api.UserRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}

	// No error - With params
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["email"] = "email@elca.ch"
		req["firstName"] = "firstname"
		req["lastName"] = "lastname"
		req["max"] = "10"
		req["username"] = "username"
		req["toto"] = "tutu" // Check this param is not transmitted
		req["group"] = "Support"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, req["group"], "email", req["email"], "firstName", req["firstName"], "lastName", req["lastName"], "max", req["max"], "username", req["username"], "group", req["group"]).Return([]api.UserRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}

	// Missing mandatory parameter group
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestGetClientRolesForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientRolesForUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var clientID = "456-789-741"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["clientID"] = clientID

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realm, userID, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestAddClientRolesToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeAddClientRolesToUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var clientID = "456-789-741"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["clientID"] = clientID
		roleJSON, _ := json.Marshal([]api.RoleRepresentation{})
		req["body"] = string(roleJSON)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realm, userID, clientID, []api.RoleRepresentation{}).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// Error - Unmarshalling error
	{
		var realm = "master"
		var userID = "123-123-456"
		var clientID = "456-789-741"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["clientID"] = clientID
		req["body"] = string("roleJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestGetRealmRolesForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmRolesForUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().GetRealmRolesForUser(ctx, realm, userID).Return([]api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestResetPasswordEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetPasswordEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		passwordJSON, _ := json.Marshal(api.PasswordRepresentation{})
		req["body"] = string(passwordJSON)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realm, userID, api.PasswordRepresentation{}).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// Error - Unmarshalling error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["body"] = string("passwordJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestSendVerifyEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendVerifyEmailEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().SendVerifyEmail(ctx, realm, userID).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// No error - With params
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["client_id"] = "123789"
		req["redirect_uri"] = "http://redirect.com"
		req["toto"] = "tutu" // Check this param is not transmitted

		mockManagementComponent.EXPECT().SendVerifyEmail(ctx, realm, userID, "client_id", req["client_id"], "redirect_uri", req["redirect_uri"]).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}
}

func TestGetRolesEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRolesEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm

		mockManagementComponent.EXPECT().GetRoles(ctx, realm).Return([]api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRoleEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var roleID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["roleID"] = roleID

		mockManagementComponent.EXPECT().GetRole(ctx, realm, roleID).Return(api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetClientRolesEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetClientRolesEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var clientID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["clientID"] = clientID

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realm, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestCreateClientRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateClientRoleEndpoint(mockManagementComponent)
	var ctx = context.Background()
	var location = "https://location.url/auth/admin/master/role/123456"
	var realm = "master"
	var clientID = "123456"

	// No error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm
		req["clientID"] = clientID
		roleJSON, _ := json.Marshal(api.RoleRepresentation{})
		req["body"] = string(roleJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, api.RoleRepresentation{}).Return(location, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/role/123456", locationHeader.URL)
	}

	// Error - Cannot unmarshall
	{
		var req = make(map[string]string)
		req["body"] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}

	// Error - Keycloak client error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm
		req["clientID"] = clientID
		userJSON, _ := json.Marshal(api.RoleRepresentation{})
		req["body"] = string(userJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, gomock.Any()).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}
}
