package management

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

func TestGetRealmsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmsEndpoint(mockManagementComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

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

func TestGetRequiredActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRequiredActionsEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm

	mockManagementComponent.EXPECT().GetRequiredActions(ctx, realm).Return([]api.RequiredActionRepresentation{}, nil).Times(1)
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
	var groups = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}

	// No error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm

		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req["body"] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, api.UserRepresentation{Groups: &groups}).Return(location, nil).Times(1)
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
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
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
		var groupID1 = "123-784dsf-sdf567"
		var groupID2 = "789-741-753"
		var groupIDs = groupID1 + "," + groupID2
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["groupIds"] = groupIDs

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{groupID1, groupID2}).Return(api.UsersPageRepresentation{}, nil).Times(1)
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
		req["search"] = "search"
		req["username"] = "username"
		req["toto"] = "tutu" // Check this param is not transmitted
		req["groupIds"] = "123-784dsf-sdf567"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{req["groupIds"]}, "email", req["email"], "firstName", req["firstName"], "lastName", req["lastName"], "username", req["username"], "search", req["search"]).Return(api.UsersPageRepresentation{}, nil).Times(1)
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

func TestGetUserAccountStatusEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserAccountStatusEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		var m map[string]bool
		m = make(map[string]bool)
		m["enabled"] = false

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realm, userID).Return(m, nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestGetRolesOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRolesOfUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().GetRolesOfUser(ctx, realm, userID).Return([]api.RoleRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestGetGroupsOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetGroupsOfUserEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().GetGroupsOfUser(ctx, realm, userID).Return([]api.GroupRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
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

		mockManagementComponent.EXPECT().ResetPassword(ctx, realm, userID, api.PasswordRepresentation{}).Return("", nil).Times(1)
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

func TestExecuteActionsEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeExecuteActionsEmailEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var actions = []api.RequiredAction{"action1", "action2"}
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		actionsJSON, _ := json.Marshal(actions)
		req["body"] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// No error - With params
	{
		var realm = "master"
		var userID = "123-456-789"
		var actions = []api.RequiredAction{"action1", "action2"}
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["client_id"] = "123789"
		req["redirect_uri"] = "http://redirect.com"
		req["toto"] = "tutu" // Check this param is not transmitted
		actionsJSON, _ := json.Marshal(actions)
		req["body"] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions, "client_id", req["client_id"], "redirect_uri", req["redirect_uri"]).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// Error - Unmarshalling error
	{

		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["client_id"] = "123789"
		req["redirect_uri"] = "http://redirect.com"
		req["body"] = string("actions")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestSendNewEnrolmentCodeEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendNewEnrolmentCodeEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().SendNewEnrolmentCode(ctx, realm, userID).Return("1234", nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{"code": "1234"}, res)

}

func TestSendReminderEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendReminderEmailEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID).Return(nil).Times(1)
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
		var lifespan = 3600
		req["realm"] = realm
		req["userID"] = userID
		req["client_id"] = "123789"
		req["redirect_uri"] = "http://redirect.com"
		req["lifespan"] = string(lifespan)
		req["toto"] = "tutu" // Check this param is not transmitted

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID, "client_id", req["client_id"], "redirect_uri", req["redirect_uri"], "lifespan", req["lifespan"]).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
		// the mock does not except to be called with req["toto"]; as the test passes it means that e has filtered out req["tutu"] and it is not transmitted to SendReminderEmail
	}
}

func TestResetSmsCounterEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetSmsCounterEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realm, userID).Return(nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)

}

func TestRecoveryCodeEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeRecoveryCodeEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().RecoveryCode(ctx, realm, userID).Return("123456", nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, "123456", res)

}

func TestGetCredentialsForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realm, userID).Return([]api.CredentialRepresentation{}, nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestDeleteCredentialsForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteCredentialsForUserEndpoint(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var credID = "987-654-321"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["credentialID"] = credID

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realm, userID, credID).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
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

func TestGetGroupsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetGroupsEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm

		mockManagementComponent.EXPECT().GetGroups(ctx, realm).Return([]api.GroupRepresentation{}, nil).Times(1)
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

func TestGetRealmCustomConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmCustomConfigurationEndpoint(mockManagementComponent)

	// No error
	{
		var realmName = "master"
		var clientID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realmName
		req["clientID"] = clientID

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(api.RealmCustomConfiguration{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	}
}

func TestUpdateRealmCustomConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

	// No error
	{
		var realmName = "master"
		var clientID = "123456"
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\"}"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realmName
		req["clientID"] = clientID
		req["body"] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// JSON error
	{
		var realmName = "master"
		var clientID = "123456"
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realmName
		req["clientID"] = clientID
		req["body"] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestConvertLocationUrl(t *testing.T) {

	res, err := convertLocationURL("http://localhost:8080/auth/realms/master/api/admin/realms/dep/users/1522-4245245-4542545/credentials", "https", "ct-bridge.services.com")
	assert.Equal(t, "https://ct-bridge.services.com/management/realms/dep/users/1522-4245245-4542545/credentials", res)
	assert.Nil(t, err)

	res, err = convertLocationURL("http://localhost:8080/auth/admin/realms/dep/users/1522-4245245-4542545", "https", "ct-bridge.services.com")
	assert.Equal(t, "https://ct-bridge.services.com/management/realms/dep/users/1522-4245245-4542545", res)
	assert.Nil(t, err)

	res, err = convertLocationURL("http://localhost:8080/toto", "https", "ct-bridge.services.com")
	assert.Equal(t, "InvalidLocation", res)
	assert.Equal(t, ConvertLocationError{Location: "http://localhost:8080/toto"}, err)

}
