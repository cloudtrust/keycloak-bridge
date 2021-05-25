package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/log"
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
	req[prmRealm] = realm

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
	req[prmRealm] = realm
	req[prmClientID] = clientID

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
	req[prmRealm] = realm

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
	req[prmRealm] = realm

	mockManagementComponent.EXPECT().GetRequiredActions(ctx, realm).Return([]api.RequiredActionRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestCreateUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateUserEndpoint(mockManagementComponent, log.NewNopLogger())

	var realm = "master"
	var location = "https://location.url/auth/admin/master/users/123456"
	var ctx = context.Background()
	var groups = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"}

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, api.UserRepresentation{Groups: &groups}, false, false).Return(location, nil).Times(1)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/users/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		userJSON, _ := json.Marshal(api.UserRepresentation{Groups: &groups})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateUser(ctx, realm, gomock.Any(), false, false).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
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
	req[prmRealm] = realm
	req[prmUserID] = userID

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
	req[prmRealm] = realm
	req[prmUserID] = userID

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

	t.Run("No error", func(t *testing.T) {
		var realm = "master"
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		userJSON, _ := json.Marshal(api.UserRepresentation{})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realm, userID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - JSON unmarshalling error", func(t *testing.T) {
		var realm = "master"
		var userID = "1234-452-4578"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[reqBody] = string("userJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestLockUserEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "1234-452-4578"
	var anyError = errors.New("any")
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("LockUser", func(t *testing.T) {
		var e = MakeLockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(nil)
			var res, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().LockUser(ctx, realm, userID).Return(anyError)
			var _, err = e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})

	t.Run("UnlockUser", func(t *testing.T) {
		var e = MakeUnlockUserEndpoint(mockManagementComponent)

		t.Run("No error", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(nil)
			var res, err = e(ctx, req)
			assert.Nil(t, err)
			assert.Nil(t, res)
		})
		t.Run("Error occured", func(t *testing.T) {
			mockManagementComponent.EXPECT().UnlockUser(ctx, realm, userID).Return(anyError)
			var _, err = e(ctx, req)
			assert.Equal(t, anyError, err)
		})
	})
}

func TestGetUsersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUsersEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var groupID1 = "123-784dsf-sdf567"
		var groupID2 = "789-741-753"
		var groupIDs = groupID1 + "," + groupID2
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmQryGroupIDs] = groupIDs

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{groupID1, groupID2}).Return(api.UsersPageRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmQryEmail] = "email@elca.ch"
		req[prmQryFirstName] = "firstname"
		req[prmQryLastName] = "lastname"
		req[prmQrySearch] = "search"
		req[prmQryUserName] = "username"
		req["toto"] = "tutu" // Check this param is not transmitted
		req[prmQryGroupIDs] = "123-784dsf-sdf567"

		mockManagementComponent.EXPECT().GetUsers(ctx, realm, []string{req[prmQryGroupIDs]}, "email", req[prmQryEmail], "firstName", req[prmQryFirstName], "lastName", req[prmQryLastName], "username", req[prmQryUserName], "search", req[prmQrySearch]).Return(api.UsersPageRepresentation{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("Missing mandatory parameter group", func(t *testing.T) {
		var realm = "master"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestMakeGetUserChecksEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserChecksEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = map[string]string{prmRealm: realm, prmUserID: userID}
		var m = []api.UserCheck{}

		mockManagementComponent.EXPECT().GetUserChecks(ctx, realm, userID).Return(m, nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetUserAccountStatusEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserAccountStatusEndpoint(mockManagementComponent)

	t.Run("No error - Without param", func(t *testing.T) {
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID
		var m = map[string]bool{"enabled": false}

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realm, userID).Return(m, nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestMakeGetUserAccountStatusByEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetUserAccountStatusByEmailEndpoint(mockManagementComponent)
	var ctx = context.Background()
	var realm = "one-realm"
	var email = "email@domain.ch"

	t.Run("MakeGetUserAccountStatusByEmailEndpoint-Missing user email", func(t *testing.T) {
		var req = map[string]string{"realm": realm}
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("MakeGetUserAccountStatusByEmailEndpoint-success", func(t *testing.T) {
		var req = map[string]string{prmRealm: realm, prmQryEmail: email}
		mockManagementComponent.EXPECT().GetUserAccountStatusByEmail(ctx, realm, email).Return(api.UserStatus{}, nil)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
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
		req[prmRealm] = realm
		req[prmUserID] = userID

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
		req[prmRealm] = realm
		req[prmUserID] = userID

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

	var realm = "master"
	var userID = "123-123-456"
	var groupID = "grp1"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmGroupID] = groupID

	t.Run("AddGroup: No error", func(t *testing.T) {
		var e = MakeAddGroupToUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().AddGroupToUser(ctx, realm, userID, groupID).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("DeleteGroup: No error", func(t *testing.T) {
		var e = MakeDeleteGroupForUserEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().DeleteGroupForUser(ctx, realm, userID, groupID).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestGetAvailableTrustIDGroupsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeGetAvailableTrustIDGroupsEndpoint(mockManagementComponent)
	var realm = "master"
	var ctx = context.Background()
	var req = map[string]string{prmRealm: realm}

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
	var req = map[string]string{prmRealm: realm, prmUserID: userID}

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
		req[prmRealm] = realm
		req[prmUserID] = userID
		body := []string{"grp1", "grp2"}
		req[reqBody] = string("[\"grp1\", \"grp2\"]")

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
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[reqBody] = ""

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
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmClientID] = clientID

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

	var realm = "master"
	var userID = "123-123-456"
	var clientID = "456-789-741"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	req[prmClientID] = clientID

	t.Run("No error", func(t *testing.T) {
		roleJSON, _ := json.Marshal([]api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realm, userID, clientID, []api.RoleRepresentation{}).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("roleJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestResetPasswordEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetPasswordEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-123-456"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error", func(t *testing.T) {
		passwordJSON, _ := json.Marshal(api.PasswordRepresentation{})
		req[reqBody] = string(passwordJSON)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realm, userID, api.PasswordRepresentation{}).Return("", nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[reqBody] = string("passwordJSON")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestExecuteActionsEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeExecuteActionsEmailEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var actions = []api.RequiredAction{"action1", "action2"}
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		actionsJSON, _ := json.Marshal(actions)
		req[reqBody] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req["toto"] = "tutu" // Check this param is not transmitted
		actionsJSON, _ := json.Marshal(actions)
		req[reqBody] = string(actionsJSON)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realm, userID, actions, prmQryClientID, req[prmQryClientID], prmQryRedirectURI, req[prmQryRedirectURI]).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("Error - Unmarshalling error", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[reqBody] = string("actions")

		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendSmsCodeEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendSmsCodeEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().SendSmsCode(ctx, realm, userID).Return("1234", nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{"code": "1234"}, res)

}

func TestSendOnboardingEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var lifespan = int(100 * time.Hour)
	var e = MakeSendOnboardingEmailEndpoint(mockManagementComponent, lifespan)

	var realm = "master"
	var customerRealm = "customer"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("Without reminder or customerRealm parameter", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is false", func(t *testing.T) {
		req[prmQryReminder] = "FALse"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, false, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is true", func(t *testing.T) {
		req[prmQryReminder] = "TruE"
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, realm, true, nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Reminder is valid, lifespan not used", func(t *testing.T) {
		req[prmQryReminder] = "false"
		req[prmQryRealm] = customerRealm
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, nil).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = "not-a-number"
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Too high lifespan submitted", func(t *testing.T) {
		req[prmQryLifespan] = strconv.Itoa(int(500 * time.Hour))
		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("Valid lifespan submitted", func(t *testing.T) {
		var lifespan = int(3 * 24 * time.Hour / time.Second)
		req[prmQryLifespan] = strconv.Itoa(lifespan)
		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realm, userID, customerRealm, false, &lifespan).Return(nil)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
}

func TestSendReminderEmailEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeSendReminderEmailEndpoint(mockManagementComponent)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID

	t.Run("No error - Without param", func(t *testing.T) {
		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("No error - With params", func(t *testing.T) {
		req[prmQryClientID] = "123789"
		req[prmQryRedirectURI] = "http://redirect.com"
		req[prmQryLifespan] = strconv.Itoa(3600)
		req["toto"] = "tutu" // Check this param is not transmitted

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realm, userID, prmQryClientID, req[prmQryClientID], prmQryRedirectURI, req[prmQryRedirectURI], prmQryLifespan, req[prmQryLifespan]).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
		// the mock does not except to be called with req["toto"]; as the test passes it means that e has filtered out req["tutu"] and it is not transmitted to SendReminderEmail
	})
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
	req[prmRealm] = realm
	req[prmUserID] = userID

	mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realm, userID).Return(nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.Nil(t, res)

}

func TestCodeEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var realm = "master"
	var userID = "123-456-789"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmUserID] = userID
	var responseCode = "123456"

	t.Run("RecoveryCode", func(t *testing.T) {
		var e = MakeCreateRecoveryCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realm, userID).Return(responseCode, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})

	t.Run("ActivationCode", func(t *testing.T) {
		var e = MakeCreateActivationCodeEndpoint(mockManagementComponent)
		mockManagementComponent.EXPECT().CreateActivationCode(ctx, realm, userID).Return(responseCode, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, responseCode, res)
	})
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
		req[prmRealm] = realm
		req[prmUserID] = userID

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
		req[prmRealm] = realm
		req[prmUserID] = userID
		req[prmCredentialID] = credID

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realm, userID, credID).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	}
}

func TestResetCredentialFailuresForUserEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeResetCredentialFailuresForUserEndpoint(mockManagementComponent)
	var ctx = context.Background()
	var req = make(map[string]string)

	t.Run("Valid query", func(t *testing.T) {
		var realm = "the-realm"
		var user = "the-user"
		var credential = "the-credential"
		mockManagementComponent.EXPECT().ResetCredentialFailuresForUser(ctx, realm, user, credential).Return(nil)
		req[prmRealm] = realm
		req[prmUserID] = user
		req[prmCredentialID] = credential
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestBruteForceEndpoints(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	t.Run("MakeClearUserLoginFailures. No error. Without param", func(t *testing.T) {
		var e = MakeClearUserLoginFailures(mockManagementComponent)
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realm, userID).Return(nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})

	t.Run("MakeGetAttackDetectionStatus. No error. Without param", func(t *testing.T) {
		var e = MakeGetAttackDetectionStatus(mockManagementComponent)
		var realm = "master"
		var userID = "123-456-789"
		var ctx = context.Background()
		var req = make(map[string]string)
		req[prmRealm] = realm
		req[prmUserID] = userID

		mockManagementComponent.EXPECT().GetAttackDetectionStatus(ctx, realm, userID).Return(api.AttackDetectionStatusRepresentation{}, nil).Times(1)
		var _, err = e(ctx, req)
		assert.Nil(t, err)
	})
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
		req[prmRealm] = realm

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
		req[prmRealm] = realm
		req[prmRoleID] = roleID

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
		req[prmRealm] = realm

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

	var e = MakeCreateGroupEndpoint(mockManagementComponent, log.NewNopLogger())

	var realm = "master"
	var location = "https://location.url/auth/admin/master/groups/123456"
	var ctx = context.Background()

	var name = "name"

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm

		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, api.GroupRepresentation{Name: &name}).Return(location, nil).Times(1)
		res, err := e(ctx, req)
		assert.Nil(t, err)

		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/groups/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		groupJSON, _ := json.Marshal(api.GroupRepresentation{Name: &name})
		req[reqBody] = string(groupJSON)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realm, gomock.Any()).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
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
	req[prmRealm] = realm
	req[prmGroupID] = groupID

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
		req[prmRealm] = realm
		req[prmGroupID] = groupID

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
		req[prmRealm] = realm
		req[prmClientID] = clientID

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

	var realmName = "master"
	var groupID = "123456"
	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = realmName
	req[prmGroupID] = groupID

	t.Run("No error", func(t *testing.T) {
		req[reqBody] = `{"matrix":{}}`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("JSON error", func(t *testing.T) {
		req[reqBody] = `{"DefaultClientId":"clientId", "DefaultRedirectUri":"http://cloudtrust.io"`

		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})
}

func TestCreateClientRoleEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var e = MakeCreateClientRoleEndpoint(mockManagementComponent, log.NewNopLogger())
	var ctx = context.Background()
	var location = "https://location.url/auth/admin/master/role/123456"
	var realm = "master"
	var clientID = "123456"

	t.Run("No error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		req[prmClientID] = clientID
		roleJSON, _ := json.Marshal(api.RoleRepresentation{})
		req[reqBody] = string(roleJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, api.RoleRepresentation{}).Return(location, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		locationHeader := res.(LocationHeader)
		assert.Equal(t, "https://elca.ch/management/master/role/123456", locationHeader.URL)
	})

	t.Run("Error - Cannot unmarshall", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqBody] = string("JSON")
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Error - Keycloak client error", func(t *testing.T) {
		var req = make(map[string]string)
		req[reqScheme] = "https"
		req[reqHost] = "elca.ch"
		req[prmRealm] = realm
		req[prmClientID] = clientID
		userJSON, _ := json.Marshal(api.RoleRepresentation{})
		req[reqBody] = string(userJSON)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realm, clientID, gomock.Any()).Return("", fmt.Errorf("Error")).Times(1)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})
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
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID}
		var e = MakeGetRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(api.RealmCustomConfiguration{}, nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.NotNil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - No error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\"}"
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeUpdateRealmCustomConfigurationEndpoint - JSON error", func(t *testing.T) {
		var configJSON = "{\"DefaultClientId\":\"clientId\", \"DefaultRedirectUri\":\"http://cloudtrust.io\""
		var req = map[string]string{prmRealm: realmName, prmClientID: clientID, reqBody: configJSON}
		var e = MakeUpdateRealmCustomConfigurationEndpoint(mockManagementComponent)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(0)
		var res, err = e(ctx, req)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	})

	t.Run("MakeGetRealmBackOfficeConfigurationEndpoint", func(t *testing.T) {
		var req = map[string]string{prmRealm: realmName, prmQryGroupName: groupName}
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
		var req = map[string]string{prmRealm: realmName, prmQryGroupName: groupName, reqBody: string(configJSON)}
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
		req[prmRealm] = realmName

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
		req[prmRealm] = realmName

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
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, gomock.Any()).Return(nil).Times(1)
		var res, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Nil(t, res)
	})
	t.Run("Invalid body content", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{}`
		var req = make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

		var _, err = e(ctx, req)
		assert.NotNil(t, err)
	})
	t.Run("JSON error", func(t *testing.T) {
		var realmName = "master"
		var configJSON = `{`
		var req = make(map[string]string)
		req[prmRealm] = realmName
		req[reqBody] = configJSON

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
	req[prmUserID] = userID
	req[prmProvider] = provider
	req[prmRealm] = realm

	fedID, _ := json.Marshal(api.FederatedIdentityRepresentation{Username: &username, UserID: &userID})
	req[reqBody] = string(fedID)

	// No error
	t.Run("Create shadow user successfully", func(t *testing.T) {
		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realm, userID, provider, api.FederatedIdentityRepresentation{Username: &username, UserID: &userID}).Return(nil).Times(1)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

	// Error
	t.Run("Create shadow user - error at unmarshal", func(t *testing.T) {
		var req2 = map[string]string{reqBody: "JSON"}
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
