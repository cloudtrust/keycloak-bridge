package management

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"go.uber.org/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func ignoreFirst(_ interface{}, err error) error {
	return err
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
	var customerRealm = "customer"
	var targetRealm = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "741-865-741"
	var userUsername = "toto"
	var email = "toto@domain.ch"

	var roleName = "role"

	var groupID = "123-789-454"
	var targetGroupID = "123-789-454"
	var groupIDs = []string{groupID}
	var groupName = "titi"
	var grpNames = []string{"grp1", "grp2"}

	var authzMatrix = map[string]map[string]map[string]struct{}{}
	var action = "TestAction"

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
	var updatableUser = api.UpdatableUserRepresentation{
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

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil).AnyTimes()

		var tests = map[string]error{
			"GetActions":                          ignoreFirst(authorizationMW.GetActions(ctx)),
			"GetRealms":                           ignoreFirst(authorizationMW.GetRealms(ctx)),
			"GetRealm":                            ignoreFirst(authorizationMW.GetRealm(ctx, realmName)),
			"GetClient":                           ignoreFirst(authorizationMW.GetClient(ctx, realmName, clientID)),
			"GetClients":                          ignoreFirst(authorizationMW.GetClients(ctx, realmName)),
			"GetRequiredActions":                  ignoreFirst(authorizationMW.GetRequiredActions(ctx, realmName)),
			"DeleteUser":                          authorizationMW.DeleteUser(ctx, realmName, userID),
			"GetUser":                             ignoreFirst(authorizationMW.GetUser(ctx, realmName, userID)),
			"UpdateUser":                          authorizationMW.UpdateUser(ctx, realmName, userID, updatableUser),
			"LockUser":                            authorizationMW.LockUser(ctx, realmName, userID),
			"UnlockUser":                          authorizationMW.UnlockUser(ctx, realmName, userID),
			"GetUsers":                            ignoreFirst(authorizationMW.GetUsers(ctx, realmName, groupIDs)),
			"CreateUser":                          ignoreFirst(authorizationMW.CreateUser(ctx, realmName, user, false, false, false)),
			"CreateUserInSocialRealm":             ignoreFirst(authorizationMW.CreateUserInSocialRealm(ctx, user, false)),
			"GetUserChecks":                       ignoreFirst(authorizationMW.GetUserChecks(ctx, realmName, userID)),
			"GetUserAccountStatus":                ignoreFirst(authorizationMW.GetUserAccountStatus(ctx, realmName, userID)),
			"GetUserAccountStatusByEmail":         ignoreFirst(authorizationMW.GetUserAccountStatusByEmail(ctx, realmName, email)),
			"GetRolesOfUser":                      ignoreFirst(authorizationMW.GetRolesOfUser(ctx, realmName, userID)),
			"AddRoleToUser":                       authorizationMW.AddRoleToUser(ctx, realmName, userID, roleID),
			"DeleteRoleForUser":                   authorizationMW.DeleteRoleForUser(ctx, realmName, userID, roleID),
			"GetGroupsOfUser":                     ignoreFirst(authorizationMW.GetGroupsOfUser(ctx, realmName, userID)),
			"AddGroupToUser":                      authorizationMW.AddGroupToUser(ctx, realmName, userID, groupID),
			"DeleteGroupForUser":                  authorizationMW.DeleteGroupForUser(ctx, realmName, userID, groupID),
			"GetAvailableTrustIDGroups":           ignoreFirst(authorizationMW.GetAvailableTrustIDGroups(ctx, realmName)),
			"GetTrustIDGroupsOfUser":              ignoreFirst(authorizationMW.GetTrustIDGroupsOfUser(ctx, realmName, userID)),
			"SetTrustIDGroupsToUser":              authorizationMW.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames),
			"GetClientRolesForUser":               ignoreFirst(authorizationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)),
			"AddClientRolesToUser":                authorizationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles),
			"DeleteClientRolesFromUser":           authorizationMW.DeleteClientRolesFromUser(ctx, realmName, userID, clientID, roleID, roleName),
			"ResetPassword":                       ignoreFirst(authorizationMW.ResetPassword(ctx, realmName, userID, password)),
			"ExecuteActionsEmail":                 authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{}),
			"SendSmsCode":                         ignoreFirst(authorizationMW.SendSmsCode(ctx, realmName, userID)),
			"SendOnboardingEmail":                 authorizationMW.SendOnboardingEmail(ctx, realmName, userID, customerRealm, false),
			"SendOnboardingEmailInSocialRealm":    authorizationMW.SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false),
			"SendReminderEmail":                   authorizationMW.SendReminderEmail(ctx, realmName, userID),
			"ResetSmsCounter":                     authorizationMW.ResetSmsCounter(ctx, realmName, userID),
			"CreateRecoveryCode":                  ignoreFirst(authorizationMW.CreateRecoveryCode(ctx, realmName, userID)),
			"CreateActivationCode":                ignoreFirst(authorizationMW.CreateActivationCode(ctx, realmName, userID)),
			"GetCredentialsForUser":               ignoreFirst(authorizationMW.GetCredentialsForUser(ctx, realmName, userID)),
			"DeleteCredentialsForUser":            authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID),
			"ResetCredentialFailuresForUser":      authorizationMW.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID),
			"ClearUserLoginFailures":              authorizationMW.ClearUserLoginFailures(ctx, realmName, userID),
			"GetAttackDetectionStatus":            ignoreFirst(authorizationMW.GetAttackDetectionStatus(ctx, realmName, userID)),
			"GetRoles":                            ignoreFirst(authorizationMW.GetRoles(ctx, realmName)),
			"GetRole":                             ignoreFirst(authorizationMW.GetRole(ctx, realmName, roleID)),
			"CreateRole":                          ignoreFirst(authorizationMW.CreateRole(ctx, realmName, role)),
			"UpdateRole":                          authorizationMW.UpdateRole(ctx, realmName, roleID, role),
			"DeleteRole":                          authorizationMW.DeleteRole(ctx, realmName, roleID),
			"GetGroups":                           ignoreFirst(authorizationMW.GetGroups(ctx, realmName)),
			"CreateGroup":                         ignoreFirst(authorizationMW.CreateGroup(ctx, realmName, group)),
			"DeleteGroup":                         authorizationMW.DeleteGroup(ctx, realmName, groupID),
			"GetAuthorizations":                   ignoreFirst(authorizationMW.GetAuthorizations(ctx, realmName, groupID)),
			"UpdateAuthorizations":                authorizationMW.UpdateAuthorizations(ctx, realmName, groupID, authz),
			"AddAuthorization":                    authorizationMW.AddAuthorization(ctx, realmName, groupID, authz),
			"GetAuthorization":                    ignoreFirst(authorizationMW.GetAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action)),
			"DeleteAuthorization":                 authorizationMW.DeleteAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action),
			"GetClientRoles":                      ignoreFirst(authorizationMW.GetClientRoles(ctx, realmName, clientID)),
			"CreateClientRole":                    ignoreFirst(authorizationMW.CreateClientRole(ctx, realmName, clientID, role)),
			"DeleteClientRole":                    authorizationMW.DeleteClientRole(ctx, realmName, clientID, roleID),
			"GetRealmCustomConfiguration":         ignoreFirst(authorizationMW.GetRealmCustomConfiguration(ctx, realmName)),
			"UpdateRealmCustomConfiguration":      authorizationMW.UpdateRealmCustomConfiguration(ctx, realmName, customConfig),
			"GetRealmAdminConfiguration":          ignoreFirst(authorizationMW.GetRealmAdminConfiguration(ctx, realmName)),
			"UpdateRealmAdminConfiguration":       authorizationMW.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig),
			"GetRealmBackOfficeConfiguration":     ignoreFirst(authorizationMW.GetRealmBackOfficeConfiguration(ctx, realmName, groupID)),
			"UpdateRealmBackOfficeConfiguration":  authorizationMW.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, boConfig),
			"GetUserRealmBackOfficeConfiguration": ignoreFirst(authorizationMW.GetUserRealmBackOfficeConfiguration(ctx, realmName)),
			"GetFederatedIdentities":              ignoreFirst(authorizationMW.GetFederatedIdentities(ctx, realmName, userID)),
			"LinkShadowUser":                      authorizationMW.LinkShadowUser(ctx, realmName, userID, provider, fedID),
			"GetIdentityProviders":                ignoreFirst(authorizationMW.GetIdentityProviders(ctx, realmName)),
		}
		for testName, testResult := range tests {
			t.Run(testName, func(t *testing.T) {
				assert.Equal(t, security.ForbiddenError{}, testResult)
			})
		}
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
	var customerRealm = "customer"
	var targetRealm = "master"
	var groups = []string{"toe"}

	var userID = "123-456-789"
	var clientID = "789-789-741"
	var roleID = "456-852-785"
	var credentialID = "7845-785-1545"
	var userUsername = "toto"
	var email = "toto@domain.ch"

	var roleName = "role"
	var toe = "toe"
	var any = "*"

	var groupID = "123-789-454"
	var targetGroupID = "123-789-454"
	var groupIDs = []string{groupID}
	var groupName = "titi"
	var grpNames = []string{"grp1", "grp2"}

	var authzMatrix = map[string]map[string]map[string]struct{}{}
	var action = "TestAction"

	var pass = "P@ssw0rd"
	var clientURI = "https://wwww.cloudtrust.io"

	var provider = "provider"

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(gomock.Any(), accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	var user = api.UserRepresentation{
		ID:       &userID,
		Username: &userUsername,
		Groups:   &groupIDs,
	}
	var updatableUser = api.UpdatableUserRepresentation{
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

	var idp = api.IdentityProviderRepresentation{}
	var idps = []api.IdentityProviderRepresentation{idp}

	var authorizations = []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.ManagementAPI) {
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

		mockManagementComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
		_, err = authorizationMW.GetActions(ctx)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealms(ctx).Return([]api.RealmRepresentation{}, nil)
		_, err = authorizationMW.GetRealms(ctx)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealm(ctx, realmName).Return(api.RealmRepresentation{}, nil)
		_, err = authorizationMW.GetRealm(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClient(ctx, realmName, clientID).Return(api.ClientRepresentation{}, nil)
		_, err = authorizationMW.GetClient(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClients(ctx, realmName).Return([]api.ClientRepresentation{}, nil)
		_, err = authorizationMW.GetClients(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRequiredActions(ctx, realmName).Return([]api.RequiredActionRepresentation{}, nil)
		_, err = authorizationMW.GetRequiredActions(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteUser(ctx, realmName, userID).Return(nil)
		err = authorizationMW.DeleteUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUser(ctx, realmName, userID).Return(api.UserRepresentation{}, nil)
		_, err = authorizationMW.GetUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateUser(ctx, realmName, userID, updatableUser).Return(nil)
		err = authorizationMW.UpdateUser(ctx, realmName, userID, updatableUser)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().LockUser(ctx, realmName, userID).Return(nil)
		err = authorizationMW.LockUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UnlockUser(ctx, realmName, userID).Return(nil)
		err = authorizationMW.UnlockUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().GetUsers(ctx, realmName, groupIDs).Return(api.UsersPageRepresentation{}, nil)
		_, err = authorizationMW.GetUsers(ctx, realmName, groupIDs)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().CreateUser(ctx, realmName, user, true, false, false).Return("", nil)
		_, err = authorizationMW.CreateUser(ctx, realmName, user, true, false, false)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateUserInSocialRealm(ctx, user, false).Return("", nil)
		_, err = authorizationMW.CreateUserInSocialRealm(ctx, user, false)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserChecks(ctx, realmName, userID).Return([]api.UserCheck{}, nil)
		_, err = authorizationMW.GetUserChecks(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserAccountStatus(ctx, realmName, userID).Return(map[string]bool{"enabled": true}, nil)
		_, err = authorizationMW.GetUserAccountStatus(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserAccountStatusByEmail(ctx, realmName, email).Return(api.UserStatus{}, nil)
		_, err = authorizationMW.GetUserAccountStatusByEmail(ctx, realmName, email)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRolesOfUser(ctx, realmName, userID).Return([]api.RoleRepresentation{}, nil)
		_, err = authorizationMW.GetRolesOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().AddRoleToUser(ctx, realmName, userID, roleID).Return(nil)
		err = authorizationMW.AddRoleToUser(ctx, realmName, userID, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteRoleForUser(ctx, realmName, userID, roleID).Return(nil)
		err = authorizationMW.DeleteRoleForUser(ctx, realmName, userID, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetGroupsOfUser(ctx, realmName, userID).Return([]api.GroupRepresentation{}, nil)
		_, err = authorizationMW.GetGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().AddGroupToUser(ctx, realmName, userID, groupID).Return(nil)
		err = authorizationMW.AddGroupToUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().DeleteGroupForUser(ctx, realmName, userID, groupID).Return(nil)
		err = authorizationMW.DeleteGroupForUser(ctx, realmName, userID, groupID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRolesForUser(ctx, realmName, userID, clientID).Return([]api.RoleRepresentation{}, nil)
		_, err = authorizationMW.GetClientRolesForUser(ctx, realmName, userID, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().AddClientRolesToUser(ctx, realmName, userID, clientID, roles).Return(nil)
		err = authorizationMW.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteClientRolesFromUser(ctx, realmName, userID, clientID, roleID, roleName).Return(nil)
		err = authorizationMW.DeleteClientRolesFromUser(ctx, realmName, userID, clientID, roleID, roleName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetPassword(ctx, realmName, userID, password).Return("", nil)
		_, err = authorizationMW.ResetPassword(ctx, realmName, userID, password)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{}).Return(nil)
		err = authorizationMW.ExecuteActionsEmail(ctx, realmName, userID, []api.RequiredAction{})
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendSmsCode(ctx, realmName, userID).Return("1234", nil)
		_, err = authorizationMW.SendSmsCode(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendOnboardingEmail(ctx, realmName, userID, customerRealm, false).Return(nil)
		err = authorizationMW.SendOnboardingEmail(ctx, realmName, userID, customerRealm, false)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false).Return(nil)
		err = authorizationMW.SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, false)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SendReminderEmail(ctx, realmName, userID).Return(nil)
		err = authorizationMW.SendReminderEmail(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetSmsCounter(ctx, realmName, userID).Return(nil)
		err = authorizationMW.ResetSmsCounter(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateRecoveryCode(ctx, realmName, userID).Return("123456", nil)
		code, err := authorizationMW.CreateRecoveryCode(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.NotNil(t, code)

		mockManagementComponent.EXPECT().CreateActivationCode(ctx, realmName, userID).Return("123456", nil)
		code, err = authorizationMW.CreateActivationCode(ctx, realmName, userID)
		assert.Nil(t, err)
		assert.NotNil(t, code)

		mockManagementComponent.EXPECT().GetCredentialsForUser(ctx, realmName, userID).Return([]api.CredentialRepresentation{}, nil)
		_, err = authorizationMW.GetCredentialsForUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteCredentialsForUser(ctx, realmName, userID, credentialID).Return(nil)
		err = authorizationMW.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID).Return(nil)
		err = authorizationMW.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().ClearUserLoginFailures(ctx, realmName, userID).Return(nil)
		err = authorizationMW.ClearUserLoginFailures(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetAttackDetectionStatus(ctx, realmName, userID).Return(api.AttackDetectionStatusRepresentation{}, nil)
		_, err = authorizationMW.GetAttackDetectionStatus(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRoles(ctx, realmName).Return([]api.RoleRepresentation{}, nil)
		_, err = authorizationMW.GetRoles(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRole(ctx, realmName, roleID).Return(api.RoleRepresentation{}, nil)
		_, err = authorizationMW.GetRole(ctx, realmName, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateRole(ctx, realmName, role).Return("", nil)
		_, err = authorizationMW.CreateRole(ctx, realmName, role)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRole(ctx, realmName, roleID, role).Return(nil)
		err = authorizationMW.UpdateRole(ctx, realmName, roleID, role)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteRole(ctx, realmName, roleID).Return(nil)
		err = authorizationMW.DeleteRole(ctx, realmName, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetGroups(ctx, realmName).Return([]api.GroupRepresentation{}, nil)
		_, err = authorizationMW.GetGroups(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetAvailableTrustIDGroups(ctx, realmName).Return(nil, nil)
		_, err = authorizationMW.GetAvailableTrustIDGroups(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetTrustIDGroupsOfUser(ctx, realmName, userID).Return(nil, nil)
		_, err = authorizationMW.GetTrustIDGroupsOfUser(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames).Return(nil)
		err = authorizationMW.SetTrustIDGroupsToUser(ctx, realmName, userID, grpNames)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateGroup(ctx, realmName, group).Return("", nil)
		_, err = authorizationMW.CreateGroup(ctx, realmName, group)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().DeleteGroup(ctx, realmName, groupID).Return(nil)
		err = authorizationMW.DeleteGroup(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().GetAuthorizations(ctx, realmName, groupID).Return(api.AuthorizationsRepresentation{}, nil)
		_, err = authorizationMW.GetAuthorizations(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().UpdateAuthorizations(ctx, realmName, groupID, authz).Return(nil)
		err = authorizationMW.UpdateAuthorizations(ctx, realmName, groupID, authz)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().AddAuthorization(ctx, realmName, groupID, authz).Return(nil)
		err = authorizationMW.AddAuthorization(ctx, realmName, groupID, authz)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().GetAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action).Return(api.AuthorizationMessage{}, nil)
		_, err = authorizationMW.GetAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action)
		assert.Nil(t, err)

		mockKeycloakClient.EXPECT().GetGroupName(gomock.Any(), gomock.Any(), realmName, groupID).Return(groupName, nil)
		mockManagementComponent.EXPECT().DeleteAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action).Return(nil)
		err = authorizationMW.DeleteAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, action)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetClientRoles(ctx, realmName, clientID).Return([]api.RoleRepresentation{}, nil)
		_, err = authorizationMW.GetClientRoles(ctx, realmName, clientID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().CreateClientRole(ctx, realmName, clientID, role).Return("", nil)
		_, err = authorizationMW.CreateClientRole(ctx, realmName, clientID, role)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().DeleteClientRole(ctx, realmName, clientID, roleID).Return(nil)
		err = authorizationMW.DeleteClientRole(ctx, realmName, clientID, roleID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmCustomConfiguration(ctx, realmName).Return(customConfig, nil)
		_, err = authorizationMW.GetRealmCustomConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmCustomConfiguration(ctx, realmName, customConfig).Return(nil)
		err = authorizationMW.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmAdminConfiguration(ctx, realmName).Return(adminConfig, nil)
		_, err = authorizationMW.GetRealmAdminConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmAdminConfiguration(ctx, realmName, adminConfig).Return(nil)
		err = authorizationMW.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetRealmBackOfficeConfiguration(ctx, realmName, groupID).Return(config, nil)
		_, err = authorizationMW.GetRealmBackOfficeConfiguration(ctx, realmName, groupID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, config).Return(nil)
		err = authorizationMW.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupID, config)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetUserRealmBackOfficeConfiguration(ctx, realmName).Return(config, nil)
		_, err = authorizationMW.GetUserRealmBackOfficeConfiguration(ctx, realmName)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetFederatedIdentities(ctx, realmName, userID).Return(nil, nil)
		_, err = authorizationMW.GetFederatedIdentities(ctx, realmName, userID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().LinkShadowUser(ctx, realmName, userID, provider, fedID).Return(nil)
		err = authorizationMW.LinkShadowUser(ctx, realmName, userID, provider, fedID)
		assert.Nil(t, err)

		mockManagementComponent.EXPECT().GetIdentityProviders(ctx, realmName).Return(idps, nil)
		_, err = authorizationMW.GetIdentityProviders(ctx, realmName)
		assert.Nil(t, err)
	}
}

func TestGetGroupsOutput(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()
	var mockKeycloakClient = mock.NewKcClientAuth(mockCtrl)
	var mockManagementComponent = mock.NewManagementComponent(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)

	var accessToken = "TOKEN=="
	var realm = "TestRealm"
	var includedGroup1 = "IncludedGroup1"
	var includedGroup2 = "IncludedGroup2"
	var notIncludedGroup = "NotIncludedGroup"
	var all = "*"
	var groups = []api.GroupRepresentation{
		{
			Name: &includedGroup1,
		}, {
			Name: &includedGroup2,
		},
	}

	var authorizations = []configuration.Authorization{
		{
			RealmID:         &realm,
			GroupName:       &includedGroup1,
			Action:          &security.MGMTGetGroups.Name,
			TargetRealmID:   &realm,
			TargetGroupName: &all,
		},
		{
			RealmID:         &realm,
			GroupName:       &includedGroup1,
			Action:          &security.MGMTIncludedInGetGroups.Name,
			TargetRealmID:   &realm,
			TargetGroupName: &includedGroup1,
		},
		{
			RealmID:         &realm,
			GroupName:       &includedGroup1,
			Action:          &security.MGMTIncludedInGetGroups.Name,
			TargetRealmID:   &realm,
			TargetGroupName: &includedGroup2,
		},
	}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextGroups, []string{includedGroup1})
	ctx = context.WithValue(ctx, cs.CtContextRealm, realm)

	t.Run("No filtering needed", func(t *testing.T) {
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authorizations, nil)
		mockManagementComponent.EXPECT().GetGroups(ctx, realm).Return(groups, nil)

		var authorizationManager, _ = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizationManager)(mockManagementComponent)

		result, err := authorizationMW.GetGroups(ctx, realm)
		assert.Nil(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("Filtering needed", func(t *testing.T) {
		groups = append(groups, api.GroupRepresentation{Name: &notIncludedGroup})
		mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authorizations, nil)
		mockManagementComponent.EXPECT().GetGroups(ctx, realm).Return(groups, nil)

		var authorizationManager, _ = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
		var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizationManager)(mockManagementComponent)

		result, err := authorizationMW.GetGroups(ctx, realm)
		assert.Nil(t, err)
		assert.Len(t, result, 2)
	})
}
