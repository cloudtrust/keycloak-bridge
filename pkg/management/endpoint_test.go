package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetActionsEndpoint(mockManagementComponent)

	var ctx = context.Background()

	mockManagementComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil).Times(1)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

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

func TestSetGroupsToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSetGroupsToUserEndpoint(mockManagementComponent)
	var realm = "master"
	var userID = "123-123-456"
	var ctx = context.Background()
	var body = []string{"grp1", "grp2"}
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID
	req["body"] = string(`["grp1", "grp2"]`)

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().SetGroupsToUser(ctx, realm, userID, body).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid input", func(t *testing.T) {
		req["body"] = string(`[`)
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
}

func TestGetAvailableTrustIDGroupsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAvailableTrustIDGroupsEndpoint(mockManagementComponent)
	var realm = "master"
	var ctx = context.Background()
	var req = map[string]string{"realm": realm}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return([]string{"grp1", "grp2"}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realm).Return(nil, errors.New("error")).Times(1)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetTrustIDGroupsOfUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetTrustIDGroupsOfUserEndpoint(mockManagementComponent)
	var realm = "master"
	var userID = "123-123-456"
	var ctx = context.Background()
	var req = map[string]string{"realm": realm, "userID": userID}

	t.Run("No error", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return([]string{"grp1", "grp2"}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Bad input", func(t *testing.T) {
		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realm, userID).Return(nil, errors.New("error")).Times(1)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestSetTrustIDGroupsToUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSetTrustIDGroupsToUserEndpoint(mockManagementComponent)

	t.Run("No error", func(t *testing.T) {
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		body := []string{"grp1", "grp2"}
		req["body"] = string("[\"grp1\", \"grp2\"]")

		mockManagementComponent.EXPECT().SetTrustIDGroupsToUser(ctx, realm, userID, body).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Bad input", func(t *testing.T) {
		var realm = "master"
		var userID = "123-123-456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID
		req["body"] = ""

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
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

	var e = MakeCreateRecoveryCodeEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["userID"] = userID

	mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realm, userID).Return("123456", nil).Times(1)
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

func TestClearUserLoginFailuresEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)
	var e = MakeClearUserLoginFailures(mockManagementComponent)

	// No error - Without param
	{
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["userID"] = userID

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realm, userID).Return(nil).Times(1)
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

func TestCreateGroupEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateGroupEndpoint(mockManagementComponent)

	var realm = "master"
	var location = "https://location.url/auth/admin/master/groups/123456"
	var ctx = context.Background()

	var name = "name"

	// No error
	{
		var req = make(map[string]string)
		req["scheme"] = "https"
		req["host"] = "elca.ch"
		req["realm"] = realm

		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req["body"] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, api.GroupRepresentation{Name: &name}).Return(location, nil).Times(1)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/groups/123456", locationHeader.URL)
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
		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req["body"] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, gomock.Any()).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	}
}

func TestDeleteGroupEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeDeleteGroupEndpoint(mockManagementComponent)

	var realm = "master"
	var groupID = "1234-452-4578"
	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = realm
	req["groupID"] = groupID

	mockManagementComponent.EXPECT().DeleteGroup(ctx, realm, groupID).Return(nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)
}

func TestGetAuthorizationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAuthorizationsEndpoint(mockManagementComponent)

	// No error
	{
		var realm = "master"
		var groupID = "123456"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realm
		req["groupID"] = groupID

		mockManagementComponent.EXPECT().GetAuthorizations(ctx, realm, groupID).Return(api.AuthorizationsRepresentation{}, nil).Times(1)
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

func TestUpdateAuthorizationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateAuthorizationsEndpoint(mockManagementComponent)

	// No error
	{
		var realmName = "master"
		var groupID = "123456"
		var authorizationsJSON = "{\"matrix\":{}}"
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realmName
		req["groupID"] = groupID
		req["body"] = authorizationsJSON

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	}

	// JSON error
	{
		var realmName = "master"
		var groupID = "123456"
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		var ctx = context.Background()
		var req = make(map[string]string)
		req["realm"] = realmName
		req["groupID"] = groupID
		req["body"] = configJSON

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
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

func TestConfigurationEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realmName = "master"
	var clientID = "123456"
	var groupName = "my-group"
	var ctx = context.Background()

	t.Run("MakeGetRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		var req = map[string]string{"realm": realmName, "clientID": clientID}
		var e = MakeGetRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(api.RealmCustomConfiguration{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\"}"
		var req = map[string]string{"realm": realmName, "clientID": clientID, "body": configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - JSON error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		var req = map[string]string{"realm": realmName, "clientID": clientID, "body": configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeGetRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var req = map[string]string{"realm": realmName, "groupName": groupName}
		var expectedConf api.BackOfficeConfiguration
		var expectedErr = errors.New("any error")
		var e = MakeGetRealmBackOfficeConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().GetRealmBackOfficeConfiguration(ctx, realmName, groupName).Return(expectedConf, expectedErr).Times(1)
		var res, err = e(ctx, req)
		assert.Equal(t, expectedErr, err)
		assert.Equal(t, expectedConf, res)
	})

	t.Run("MakeUpdateRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var config api.BackOfficeConfiguration
		var configJSON, _ = json.Marshal(config)
		var req = map[string]string{"realm": realmName, "groupName": groupName, "body": string(configJSON)}
		var expectedErr = errors.New("update error")
		var e = MakeUpdateRealmBackOfficeConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmBackOfficeConfiguration(ctx, realmName, groupName, config).Return(expectedErr).Times(1)
		var res, err = e(ctx, req)
		assert.Equal(t, expectedErr, err)
		assert.Nil(t, res)
	})
}

func TestGetRealmAdminConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetRealmAdminConfigurationEndpoint(mockManagementComponent)
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		var realmName = "master"
		var adminConfig api.RealmAdminConfiguration
		var req = make(map[string]string)
		req["realm"] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})
	t.Run("Request fails at component level", func(t *testing.T) {
		var realmName = "master"
		var adminConfig api.RealmAdminConfiguration
		var expectedError = errors.New("component error")
		var req = make(map[string]string)
		req["realm"] = realmName

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, expectedError).Times(1)
		var _, err = e(ctx, req)
		assert.Equal(t, expectedError, err)
	})
}

func TestUpdateRealmAdminConfigurationEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeUpdateRealmAdminConfigurationEndpoint(mockManagementComponent)
	var ctx = context.Background()

	t.Run("No error", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{"mode":"trustID"}`
		var req = make(map[string]string)
		req["realm"] = realmName
		req["body"] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid body content", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{}`
		var req = make(map[string]string)
		req["realm"] = realmName
		req["body"] = configJSON

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("JSON error", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{`
		var req = make(map[string]string)
		req["realm"] = realmName
		req["body"] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestLinkShadowUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeLinkShadowUserEndpoint(mockManagementComponent)

	var realm = "master"
	var ctx = context.Background()
	var username = "username"
	var userID = "abcdefgh-1234-ijkl-5678-mnopqrstuvwx"
	var provider = "provider"

	var req = make(map[string]string)
	req["userID"] = userID
	req["provider"] = provider
	req["realm"] = realm

	fedID, _ := json.Marshal(api.FederatedIdentityRepresentation{Username: &username, UserID: &userID})
	req["body"] = string(fedID)

	// No error
	t.Run("Create shadow user successfully", func(t *testing.T) {
		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realm, userID, provider, api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}).Return(nil).Times(1)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	// Error
	t.Run("Create shadow user - error at unmarshal", func(t *testing.T) {

		var req2 = make(map[string]string)
		req2["body"] = string("JSON")
		_, err := e(ctx, req2)
		assert.NotNil(t, err)
	})

	// Error - Keycloak client error
	t.Run("Create shadow user - error at KC client", func(t *testing.T) {

		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realm, userID, provider, api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}).Return(fmt.Errorf("error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
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
