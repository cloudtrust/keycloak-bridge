package management

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger

import (
	"context"
	"fmt"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestCheckAuthorisationOnRealm(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe", "svc"}

	// Authorized for all realm (test wildcard)
	{
		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"GetRealm": {"*": {} }} }}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil).Times(1)

		_, err = authorisationMW.GetRealm(ctx, "master")

		assert.Nil(t, err)
	}

	// Authorized for non admin realm
	{
		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"GetRealm": {"/": {} }} }}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		mockManagementComponent.EXPECT().GetRealm(ctx, "toto").Return(api.RealmRepresentation{}, nil).Times(1)

		_, err = authorisationMW.GetRealm(ctx, "toto")
		assert.Nil(t, err)

		_, err = authorisationMW.GetRealm(ctx, "master")
		assert.NotNil(t, err)
		assert.Equal(t, "ForbiddenError: Operation not permitted.", err.Error())

	}

	// Authorized for specific realm
	{
		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"GetRealm": {"master": {} }} }}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil).Times(1)

		_, err = authorisationMW.GetRealm(ctx, "master")
		assert.Nil(t, err)

		_, err = authorisationMW.GetRealm(ctx, "other")
		assert.Equal(t, ForbiddenError{}, err)
	}

	// Deny by default
	{
		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"CreateUser": {"master": {} }} }}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		_, err = authorisationMW.GetRealm(ctx, "master")
		assert.Equal(t, ForbiddenError{}, err)
	}
}

func TestCheckAuthorisationOnTargetUser(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var groups = []string{"toe", "svc"}
	var realm = "master"

	// Authorized for all groups (test wildcard)
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"master": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteUser(ctx, targetRealm, targetUserID).Return(nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Nil(t, err)
	}

	// Test no groups assigned to targetUser
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"master": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
		}, nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Equal(t, ForbiddenError{}, err)
	}

	// Test allowed only for non master realm
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"/": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteUser(ctx, targetRealm, targetUserID).Return(nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetUser(accessToken, "master", targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		err = authorisationMW.DeleteUser(ctx, "master", targetUserID)
		assert.Equal(t, ForbiddenError{}, err)
	}

	// Authorized for all realms (test wildcard) and all groups
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"*": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteUser(ctx, targetRealm, targetUserID).Return(nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Nil(t, err)
	}

	// Test cannot GetUser infos
	{
		var targetRealm = "master"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"*": { "*": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{}, fmt.Errorf("Error")).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Equal(t, ForbiddenError{}, err)
	}

	// Test for a specific target group
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {"toto": { "customer": {} } }} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteUser(ctx, targetRealm, targetUserID).Return(nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Nil(t, err)
	}

	// Deny
	{
		var targetRealm = "toto"
		var targetUserID = "123-456-789"

		var authorisations, err = LoadAuthorizations(`{"master": {"toe": {"DeleteUser": {}} }}`)
		assert.Nil(t, err)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", realm)

		var userId = "123-456-789"
		var userUsername = "toto"
		var userGroups = []string{"customer"}

		mockKeycloakClient.EXPECT().GetUser(accessToken, targetRealm, targetUserID).Return(kc.UserRepresentation{
			Id:       &userId,
			Username: &userUsername,
			Groups:   &userGroups,
		}, nil).Times(1)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)
		err = authorisationMW.DeleteUser(ctx, targetRealm, targetUserID)

		assert.Equal(t, ForbiddenError{}, err)
	}
}

func TestLoadAuthorisations(t *testing.T) {

	// Empty file
	{
		var jsonAuthz = ""
		_, err := LoadAuthorizations(jsonAuthz)
		assert.NotNil(t, err)
		assert.Equal(t, "JSON structure expected.", err.Error())
	}

	// Empty JSON
	{
		var jsonAuthz = "{}"
		_, err := LoadAuthorizations(jsonAuthz)
		assert.Nil(t, err)
	}

	// Wrong format
	{
		var jsonAuthz = "{sdf}ref"
		_, err := LoadAuthorizations(jsonAuthz)
		assert.NotNil(t, err)
	}

	// Correct format
	{
		var jsonAuthz = `{
			"master":{
			  "toe_administrator":{
				"GetUsers": {
				  "master": {
					"*": {}
				  }
				},
				"CreateUser": {
				  "master": {
					"integrator_manager": {},
					"integrator_agent": {},
					"l2_support_manager": {},
					"l2_support_agent": {},
					"l3_support_manager": {},
					"l3_support_agent": {}
				  }
				}
			  },
			  "l3_support_agent": {}
			},
			"DEP":{
			  "product_administrator":{
				"GetUsers": {
				  "DEP": {
					"*": {}
				  }
				},
				"CreateUser": {
				  "DEP": {
					"l1_support_manager": {}
				  }
				}
			  },
			  "l1_support_manager": {
				"GetUsers": {
				  "DEP": {
					"l1_support_agent": {},
					"end_user": {}
				  }
				}
			  }
			}
		  }`

		authorizations, err := LoadAuthorizations(jsonAuthz)
		assert.Nil(t, err)

		_, ok := authorizations["master"]["toe_administrator"]["GetUsers"]["master"]["*"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["toe_administrator"]["GetUsers"]["master"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["l3_support_agent"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["master"]["l3_support_agent"]["GetUsers"]["master"]
		assert.Equal(t, false, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]["end_user"]
		assert.Equal(t, true, ok)

		_, ok = authorizations["DEP"]["l1_support_manager"]["GetUsers"]["DEP"]["end_user2"]
		assert.Equal(t, false, ok)
	}
}

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var userUsername = "toto"
	var userGroups = []string{"customer"}
	var groupName = "titi"

	var roleName = "role"

	var pass = "P@ssw0rd"

	mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}, nil).AnyTimes()

	var user = api.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}

	var role = api.RoleRepresentation{
		Id:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	// Nothing allowed
	{
		var authorisations, err = LoadAuthorizations(`{}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		_, err = authorisationMW.GetRealm(ctx, realmName)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetClient(ctx, realmName, clientID)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetClients(ctx, realmName)
		assert.Equal(t, ForbiddenError{}, err)

		err = authorisationMW.DeleteUser(ctx, realmName, userID)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetUser(ctx, realmName, userID)
		assert.Equal(t, ForbiddenError{}, err)

		err = authorisationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetUsers(ctx, realmName, groupName)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.CreateUser(ctx, realmName, user)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Equal(t, ForbiddenError{}, err)

		err = authorisationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetRealmRolesForUser(ctx, realmName, userID)
		assert.Equal(t, ForbiddenError{}, err)

		err = authorisationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Equal(t, ForbiddenError{}, err)

		err = authorisationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetRoles(ctx, realmName)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetRole(ctx, realmName, roleID)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Equal(t, ForbiddenError{}, err)

		_, err = authorisationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Equal(t, ForbiddenError{}, err)
	}
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockKeycloakClient = mock.NewKeycloakClient(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var userUsername = "toto"
	var userGroups = []string{"customer"}

	var roleName = "role"

	var groupName = "titi"

	var pass = "P@ssw0rd"

	mockKeycloakClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}, nil).AnyTimes()

	var user = api.UserRepresentation{
		Id:       &userID,
		Username: &userUsername,
		Groups:   &userGroups,
	}

	var role = api.RoleRepresentation{
		Id:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	// Nothing allowed
	{
		var authorisations, err = LoadAuthorizations(`{"master":
			{
				"toe": {
					"GetRealm": {"*": {"*": {} }},
					"GetClient": {"*": {"*": {} }},
					"GetClients": {"*": {"*": {} }},
					"DeleteUser": {"*": {"*": {} }},
					"GetUser": {"*": {"*": {} }},
					"UpdateUser": {"*": {"*": {} }},
					"GetUsers": {"*": {"*": {} }},
					"CreateUser": {"*": {"*": {} }},
					"GetClientRolesForUser": {"*": {"*": {} }},
					"AddClientRolesToUser": {"*": {"*": {} }},
					"GetRealmRolesForUser": {"*": {"*": {} }},
					"ResetPassword": {"*": {"*": {} }},
					"SendVerifyEmail": {"*": {"*": {} }},
					"GetRoles": {"*": {"*": {} }},
					"GetRole": {"*": {"*": {} }},
					"GetClientRoles": {"*": {"*": {} }},
					"CreateClientRole": {"*": {"*": {} }}
				}
			}
		}`)
		assert.Nil(t, err)

		var authorisationMW = MakeAuthorisationManagementComponentMW(mockLogger, mockKeycloakClient, authorisations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), "access_token", accessToken)
		ctx = context.WithValue(ctx, "groups", groups)
		ctx = context.WithValue(ctx, "realm", "master")

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRealm(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClient(ctx, realmName, clientID).Return(api.ClientRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClient(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClients(ctx, realmName).Return([]api.ClientRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClients(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteUser(ctx, realmName, userID).Return(nil).Times(1)
		err = authorisationMW.DeleteUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUser(ctx, realmName, userID).Return(api.UserRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realmName, userID, user).Return(nil).Times(1)
		err = authorisationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUsers(ctx, realmName, groupName).Return([]api.UserRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetUsers(ctx, realmName, groupName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateUser(ctx, realmName, user).Return("", nil).Times(1)
		_, err = authorisationMW.CreateUser(ctx, realmName, user)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realmName, userID, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realmName, userID, clientID, roles).Return(nil).Times(1)
		err = authorisationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmRolesForUser(ctx, realmName, userID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRealmRolesForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realmName, userID, password).Return(nil).Times(1)
		err = authorisationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendVerifyEmail(ctx, realmName, userID).Return(nil).Times(1)
		err = authorisationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRoles(ctx, realmName).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRoles(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRole(ctx, realmName, roleID).Return(api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetRole(ctx, realmName, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realmName, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorisationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realmName, clientID, role).Return("", nil).Times(1)
		_, err = authorisationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Nil(t, err)
	}
}
