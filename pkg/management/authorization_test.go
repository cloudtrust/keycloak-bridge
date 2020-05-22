package management

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/configuration"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActionsString(t *testing.T) {
	assert.Len(t, GetActions(), len(actions))
}

func TestDeny(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

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
	var grpNames = []string{"grp1", "grp2"}

	var authzMatrix = map[string]map[string]map[string]struct{}{}

	var pass = "P@ssw0rd"
	var clientURI = "https://wwww.cloudtrust.io"

	var provider = "provider"
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return([]configuration.Authorization{}, nil)

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(gomock.Any(), accessToken, realmName, userID).Return([]string{
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

	var group = api.GroupRepresentation{
		Name: &groupName,
	}

	var authz = api.AuthorizationsRepresentation{
		Matrix: &authzMatrix,
	}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	var customConfig = api.RealmCustomConfiguration{
		DefaultClientID:    &clientID,
		DefaultRedirectURI: &clientURI,
	}

	var boConfig api.BackOfficeConfiguration
	var adminConfig api.RealmAdminConfiguration

	var fedID = api.FederatedIdentityRepresentation{
		UserID:   &userID,
		Username: &userUsername,
	}

	// Nothing allowed
	{
		var authorizations, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, log.NewNopLogger())
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		_, err = authorizationMW.GetActions(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealms(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealm(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClient(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClients(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRequiredActions(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.DeleteUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateUser(ctx, realmName, userID, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		_, err = authorizationMW.GetUsers(ctx, realmName, groupIDs)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		_, err = authorizationMW.CreateUser(ctx, realmName, user)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRolesOfUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetGroupsOfUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetAvailableTrustIDGroups(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{})
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.SendNewEnrolmentCode(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.SendReminderEmail(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.ResetSmsCounter(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.CreateRecoveryCode(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.ClearUserLoginFailures(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetAttackDetectionStatus(ctx, realmName, userID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRoles(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRole(ctx, realmName, roleID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetGroups(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.CreateGroup(ctx, realmName, group)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		err = authorizationMW.DeleteGroup(ctx, realmName, groupID)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		_, err = authorizationMW.GetAuthorizations(ctx, realmName, groupID)
		assert.Equal(t, security.ForbiddenError{}, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		err = authorizationMW.UpdateAuthorizations(ctx, realmName, groupID, authz)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealmCustomConfiguration(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealmAdminConfiguration(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetRealmBackOfficeConfiguration(ctx, realmName, groupID)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, boConfig)
		assert.Equal(t, security.ForbiddenError{}, err)

		_, err = authorizationMW.GetUserRealmBackOfficeConfiguration(ctx, realmName)
		assert.Equal(t, security.ForbiddenError{}, err)

		err = authorizationMW.LinkShadowUser(ctx, realmName, userID, provider, fedID)
		assert.Equal(t, security.ForbiddenError{}, err)
	}
}

func TestAllowed(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realmName = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "7845-785-1545"
	var userUsername = "toto"

	var roleName = "role"
	var toe = "toe"
	var any = "*"

	var groupID = "123-789-454"
	var groupIDs = []string{groupID}
	var groupName = "titi"
	var grpNames = []string{"grp1", "grp2"}

	var authzMatrix = map[string]map[string]map[string]struct{}{}

	var pass = "P@ssw0rd"
	var clientURI = "https://wwww.cloudtrust.io"

	var provider = "provider"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(gomock.Any(), accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

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

	var group = api.GroupRepresentation{
		Name: &groupName,
	}

	var authz = api.AuthorizationsRepresentation{
		Matrix: &authzMatrix,
	}

	var password = api.PasswordRepresentation{
		Value: &pass,
	}

	var customConfig = api.RealmCustomConfiguration{
		DefaultClientID:    &clientID,
		DefaultRedirectURI: &clientURI,
	}
	var config api.BackOfficeConfiguration
	var adminConfig api.RealmAdminConfiguration

	var fedID = api.FederatedIdentityRepresentation{
		UserID:   &userID,
		Username: &userUsername,
	}

	var authorizations = []configuration.Authorization{}
	for _, action := range actions {
		var action = string(action.Name)
		authorizations = append(authorizations, configuration.Authorization{
			RealmID:         &realmName,
			GroupName:       &toe,
			Action:          &action,
			TargetRealmID:   &any,
			TargetGroupName: &any,
		})
	}
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authorizations, nil)

	// Anything allowed
	{
		var authorizationManager, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, log.NewNopLogger())
		assert.Nil(t, err)

		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizationManager)(mockManagementComponent)

		var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
		ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
		ctx = context.WithValue(ctx, cs.CtContextRealm, "master")

		mockManagementComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetActions(ctx)
		assert.Nil(t, err)

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

		mockManagementComponent.EXPECT().GetRequiredActions(ctx, realmName).Return([]api.RequiredActionRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetRequiredActions(ctx, realmName)
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

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().GetUsers(ctx, realmName, groupIDs).Return(api.UsersPageRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetUsers(ctx, realmName, groupIDs)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
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

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().AddGroupToUser(ctx, realmName, userID, groupID).Return(nil).Times(1)
		err = authorizationMW.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteGroupForUser(ctx, realmName, userID, groupID).Return(nil).Times(1)
		err = authorizationMW.DeleteGroupForUser(ctx, realmName, userID, groupID)
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

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{}).Return(nil).Times(1)
		err = authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{})
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendNewEnrolmentCode(ctx, realmName, userID).Return("1234", nil).Times(1)
		_, err = authorizationMW.SendNewEnrolmentCode(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.SendReminderEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.ResetSmsCounter(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realmName, userID).Return("123456", nil).Times(1)
		code, err := authorizationMW.CreateRecoveryCode(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.NotNil(t, code)

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realmName, userID).Return([]api.CredentialRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realmName, userID, credentialID).Return(nil).Times(1)
		err = authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realmName, userID).Return(nil).Times(1)
		err = authorizationMW.ClearUserLoginFailures(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetAttackDetectionStatus(ctx, realmName, userID).Return(api.AttackDetectionStatusRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetAttackDetectionStatus(ctx, realmName, userID)
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

		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realmName).Return(nil, nil).Times(1)
		_, err = authorizationMW.GetAvailableTrustIDGroups(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realmName, userID).Return(nil, nil).Times(1)
		_, err = authorizationMW.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames).Return(nil).Times(1)
		err = authorizationMW.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realmName, group).Return("", nil).Times(1)
		_, err = authorizationMW.CreateGroup(ctx, realmName, group)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().DeleteGroup(ctx, realmName, groupID).Return(nil).Times(1)
		err = authorizationMW.DeleteGroup(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().GetAuthorizations(ctx, realmName, groupID).Return(api.AuthorizationsRepresentation{}, nil).Times(1)
		_, err = authorizationMW.GetAuthorizations(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).Times(1)
		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, authz).Return(nil).Times(1)
		err = authorizationMW.UpdateAuthorizations(ctx, realmName, groupID, authz)
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

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, nil).Times(1)
		_, err = authorizationMW.GetRealmAdminConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, adminConfig).Return(nil).Times(1)
		err = authorizationMW.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmBackOfficeConfiguration(ctx, realmName, groupID).Return(config, nil).Times(1)
		_, err = authorizationMW.GetRealmBackOfficeConfiguration(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, config).Return(nil).Times(1)
		err = authorizationMW.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, config)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserRealmBackOfficeConfiguration(ctx, realmName).Return(config, nil).Times(1)
		_, err = authorizationMW.GetUserRealmBackOfficeConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realmName, userID, provider, fedID).Return(nil).Times(1)
		err = authorizationMW.LinkShadowUser(ctx, realmName, userID, provider, fedID)
		assert.Nil(t, err)
	}
}
