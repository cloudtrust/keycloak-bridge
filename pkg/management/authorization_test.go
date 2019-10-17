package management

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "741-865-741"
	var userUsername = "toto"

	var roleName = "role"

	var groupID = "123-789-454"
	var groupIDs = []string{groupID}
	var groupName = "titi"

	var pass = "P@ssw0rd"
	var clientURI = "https://wwww.cloudtrust.io"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(accessToken, realmName, userID).Return([]string{
		groupName,
	}, nil).AnyTimes()

	var user = api.UserRepresentation{
		ID:       &userID,
		Username: &userUsername,
		Groups:   &groupIDs,
	}

	var role = api.RoleRepresentation{
		ID:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	var customConfig = api.RealmCustomConfiguration{
		DefaultClientID:    &clientID,
		DefaultRedirectURI: &clientURI,
	}

	// Nothing allowed
	{
		var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, log.NewNopLogger(), `{}`)
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		_, err = authorizationMW.GetRealms(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealm(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClient(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClients(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.DeleteUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		_, err = authorizationMW.GetUsers(ctx, realmName, groupIDs)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		_, err = authorizationMW.CreateUser(ctx, realmName, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRolesOfUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetGroupsOfUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{})
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.SendNewEnrolmentCode(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SendReminderEmail(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRoles(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRole(ctx, realmName, roleID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetGroups(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealmCustomConfiguration(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
		assert.Equal(t, security.ForbiddenError{}, err)
	}
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "7845-785-1545"
	var userUsername = "toto"

	var roleName = "role"

	var groupID = "123-789-454"
	var groupIDs = []string{groupID}
	var groupName = "titi"

	var pass = "P@ssw0rd"
	var clientURI = "https://wwww.cloudtrust.io"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	var user = api.UserRepresentation{
		ID:       &userID,
		Username: &userUsername,
		Groups:   &groupIDs,
	}

	var role = api.RoleRepresentation{
		ID:   &roleID,
		Name: &roleName,
	}

	var roles = []api.RoleRepresentation{role}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	var customConfig = api.RealmCustomConfiguration{
		DefaultClientID:    &clientID,
		DefaultRedirectURI: &clientURI,
	}

	// Anything allowed
	{
		var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, log.NewNopLogger(), `{"master":
			{
				"toe": {
					"GetRealms": {"*": {}},
					"GetRealm": {"*": {"*": {} }},
					"GetClient": {"*": {"*": {} }},
					"GetClients": {"*": {"*": {} }},
					"DeleteUser": {"*": {"*": {} }},
					"GetUser": {"*": {"*": {} }},
					"UpdateUser": {"*": {"*": {} }},
					"GetUsers": {"*": {"*": {} }},
					"CreateUser": {"*": {"*": {} }},
					"GetUserAccountStatus": {"*": {"*": {} }},
					"GetRolesOfUser": {"*": {"*": {} }},
					"GetGroupsOfUser": {"*": {"*": {} }},
					"GetClientRolesForUser": {"*": {"*": {} }},
					"AddClientRolesToUser": {"*": {"*": {} }},
					"ResetPassword": {"*": {"*": {} }},
					"SendVerifyEmail": {"*": {"*": {} }},
					"ExecuteActionsEmail": {"*": {"*": {} }},
					"SendNewEnrolmentCode": {"*": {"*": {} }},
					"SendReminderEmail": {"*": {"*": {} }},
					"GetCredentialsForUser": {"*": {"*": {} }},
					"DeleteCredentialsForUser": {"*": {"*": {} }},
					"GetRoles": {"*": {"*": {} }},
					"GetRole": {"*": {"*": {} }},
					"GetGroups": {"*": {"*": {} }},
					"GetClientRoles": {"*": {"*": {} }},
					"CreateClientRole": {"*": {"*": {} }},
					"GetRealmCustomConfiguration": {"*": {"*": {} }},
					"UpdateRealmCustomConfiguration": {"*": {"*": {} }}
				}
			}
		}`)
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRealms(ctx)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRealm(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClient(ctx, realmName, clientID).Return(api.ClientRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetClient(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClients(ctx, realmName).Return([]api.ClientRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetClients(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteUser(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.DeleteUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUser(ctx, realmName, userID).Return(api.UserRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realmName, userID, user).Return(nil).Times(1)
		err = authorizationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().GetUsers(ctx, realmName, groupIDs).Return(api.UsersPageRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetUsers(ctx, realmName, groupIDs)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().CreateUser(ctx, realmName, user).Return("", nil).Times(1)
		_, err = authorizationMW.CreateUser(ctx, realmName, user)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realmName, userID).Return(map[string]bool{"enabled": true}, nil).Times(1)
		_, err = authorizationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRolesOfUser(ctx, realmName, userID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRolesOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetGroupsOfUser(ctx, realmName, userID).Return([]api.GroupRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realmName, userID, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realmName, userID, clientID, roles).Return(nil).Times(1)
		err = authorizationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realmName, userID, password).Return("", nil).Times(1)
		_, err = authorizationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendVerifyEmail(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.SendVerifyEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{}).Return(nil).Times(1)
		err = authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{})
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendNewEnrolmentCode(ctx, realmName, userID).Return("1234", nil).Times(1)
		_, err = authorizationMW.SendNewEnrolmentCode(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.SendReminderEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realmName, userID).Return([]api.CredentialRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realmName, userID, credentialID).Return(nil).Times(1)
		err = authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRoles(ctx, realmName).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRoles(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRole(ctx, realmName, roleID).Return(api.RoleRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRole(ctx, realmName, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetGroups(ctx, realmName).Return([]api.GroupRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetGroups(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realmName, clientID).Return([]api.RoleRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realmName, clientID, role).Return("", nil).Times(1)
		_, err = authorizationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(customConfig, nil).Times(1)
		_, err = authorizationMW.GetRealmCustomConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, customConfig).Return(nil).Times(1)
		err = authorizationMW.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
		assert.Nil(t, err)
	}
}
