package management

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
)

var actions []security.Action

func newAction(as string, scope security.Scope) security.Action {
	a := security.Action{
		Name:  as,
		Scope: scope,
	}

	actions = append(actions, a)
	return a
}

// Creates constants for API method names
var (
	MGMTGetActions                          = newAction("MGMT_GetActions", security.ScopeGlobal)
	MGMTGetRealms                           = newAction("MGMT_GetRealms", security.ScopeGlobal)
	MGMTGetRealm                            = newAction("MGMT_GetRealm", security.ScopeRealm)
	MGMTGetClient                           = newAction("MGMT_GetClient", security.ScopeRealm)
	MGMTGetClients                          = newAction("MGMT_GetClients", security.ScopeRealm)
	MGMTGetRequiredActions                  = newAction("MGMT_GetRequiredActions", security.ScopeRealm)
	MGMTDeleteUser                          = newAction("MGMT_DeleteUser", security.ScopeGroup)
	MGMTGetUser                             = newAction("MGMT_GetUser", security.ScopeGroup)
	MGMTUpdateUser                          = newAction("MGMT_UpdateUser", security.ScopeGroup)
	MGMTGetUsers                            = newAction("MGMT_GetUsers", security.ScopeGroup)
	MGMTCreateUser                          = newAction("MGMT_CreateUser", security.ScopeGroup)
	MGMTGetUserAccountStatus                = newAction("MGMT_GetUserAccountStatus", security.ScopeGroup)
	MGMTGetRolesOfUser                      = newAction("MGMT_GetRolesOfUser", security.ScopeGroup)
	MGMTGetGroupsOfUser                     = newAction("MGMT_GetGroupsOfUser", security.ScopeGroup)
	MGMTSetTrustIDGroups                    = newAction("MGMT_SetTrustIDGroups", security.ScopeGroup)
	MGMTGetClientRolesForUser               = newAction("MGMT_GetClientRolesForUser", security.ScopeGroup)
	MGMTAddClientRolesToUser                = newAction("MGMT_AddClientRolesToUser", security.ScopeGroup)
	MGMTResetPassword                       = newAction("MGMT_ResetPassword", security.ScopeGroup)
	MGMTExecuteActionsEmail                 = newAction("MGMT_ExecuteActionsEmail", security.ScopeGroup)
	MGMTSendNewEnrolmentCode                = newAction("MGMT_SendNewEnrolmentCode", security.ScopeGroup)
	MGMTSendReminderEmail                   = newAction("MGMT_SendReminderEmail", security.ScopeGroup)
	MGMTResetSmsCounter                     = newAction("MGMT_ResetSmsCounter", security.ScopeGroup)
	MGMTCreateRecoveryCode                  = newAction("MGMT_CreateRecoveryCode", security.ScopeGroup)
	MGMTGetCredentialsForUser               = newAction("MGMT_GetCredentialsForUser", security.ScopeGroup)
	MGMTDeleteCredentialsForUser            = newAction("MGMT_DeleteCredentialsForUser", security.ScopeGroup)
	MGMTGetRoles                            = newAction("MGMT_GetRoles", security.ScopeRealm)
	MGMTGetRole                             = newAction("MGMT_GetRole", security.ScopeRealm)
	MGMTGetGroups                           = newAction("MGMT_GetGroups", security.ScopeRealm)
	MGMTCreateGroup                         = newAction("MGMT_CreateGroup", security.ScopeRealm)
	MGMTDeleteGroup                         = newAction("MGMT_DeleteGroup", security.ScopeGroup)
	MGMTGetAuthorizations                   = newAction("MGMT_GetAuthorizations", security.ScopeGroup)
	MGMTUpdateAuthorizations                = newAction("MGMT_UpdateAuthorizations", security.ScopeGroup)
	MGMTGetClientRoles                      = newAction("MGMT_GetClientRoles", security.ScopeRealm)
	MGMTCreateClientRole                    = newAction("MGMT_CreateClientRole", security.ScopeRealm)
	MGMTGetRealmCustomConfiguration         = newAction("MGMT_GetRealmCustomConfiguration", security.ScopeRealm)
	MGMTUpdateRealmCustomConfiguration      = newAction("MGMT_UpdateRealmCustomConfiguration", security.ScopeRealm)
	MGMTGetRealmBackOfficeConfiguration     = newAction("MGMT_GetRealmBackOfficeConfiguration", security.ScopeGroup)
	MGMTUpdateRealmBackOfficeConfiguration  = newAction("MGMT_UpdateRealmBackOfficeConfiguration", security.ScopeGroup)
	MGMTGetUserRealmBackOfficeConfiguration = newAction("MGMT_GetUserRealmBackOfficeConfiguration", security.ScopeRealm)
	MGMTCreateShadowUser                    = newAction("MGMT_CreateShadowUser", security.ScopeRealm)
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorizationManagementComponentMW checks authorization and return an error if the action is not allowed.
func MakeAuthorizationManagementComponentMW(logger log.Logger, authorizationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorizationComponentMW{
			authManager: authorizationManager,
			logger:      logger,
			next:        next,
		}
	}
}

func (c *authorizationComponentMW) GetActions(ctx context.Context) ([]api.ActionRepresentation, error) {
	var action = MGMTGetActions.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var action = MGMTGetRealms.String()
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RealmRepresentation{}, err
	}

	return c.next.GetRealms(ctx)
}

func (c *authorizationComponentMW) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var action = MGMTGetRealm.String()
	var targetRealm = realm

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmRepresentation{}, err
	}

	return c.next.GetRealm(ctx, realm)
}

func (c *authorizationComponentMW) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var action = MGMTGetClient.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.ClientRepresentation{}, err
	}

	return c.next.GetClient(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var action = MGMTGetClients.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ClientRepresentation{}, err
	}

	return c.next.GetClients(ctx, realmName)
}

func (c *authorizationComponentMW) GetRequiredActions(ctx context.Context, realmName string) ([]api.RequiredActionRepresentation, error) {
	var action = MGMTGetRequiredActions.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RequiredActionRepresentation{}, err
	}

	return c.next.GetRequiredActions(ctx, realmName)
}

func (c *authorizationComponentMW) DeleteUser(ctx context.Context, realmName, userID string) error {
	var action = MGMTDeleteUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var action = MGMTGetUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var action = MGMTUpdateUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorizationComponentMW) GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error) {
	var action = MGMTGetUsers.String()
	var targetRealm = realmName

	for _, groupID := range groupIDs {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
			return api.UsersPageRepresentation{}, err
		}
	}

	return c.next.GetUsers(ctx, realmName, groupIDs, paramKV...)
}

func (c *authorizationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var action = MGMTCreateUser.String()
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user)
}

func (c *authorizationComponentMW) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var action = MGMTGetUserAccountStatus.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserAccountStatus(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = MGMTGetRolesOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRolesOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var action = MGMTGetGroupsOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.GroupRepresentation{}, err
	}

	return c.next.GetGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SetTrustIDGroups(ctx context.Context, realmName, userID string, groupNames []string) error {
	var action = MGMTSetTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SetTrustIDGroups(ctx, realmName, userID, groupNames)
}

func (c *authorizationComponentMW) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var action = MGMTGetClientRolesForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRolesForUser(ctx, realmName, userID, clientID)
}

func (c *authorizationComponentMW) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var action = MGMTAddClientRolesToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
}

func (c *authorizationComponentMW) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error) {
	var action = MGMTResetPassword.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.ResetPassword(ctx, realmName, userID, password)
}

func (c *authorizationComponentMW) CreateRecoveryCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = MGMTCreateRecoveryCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.CreateRecoveryCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error {
	var action = MGMTExecuteActionsEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ExecuteActionsEmail(ctx, realmName, userID, actions, paramKV...)
}

func (c *authorizationComponentMW) SendNewEnrolmentCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = MGMTSendNewEnrolmentCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.SendNewEnrolmentCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var action = MGMTSendReminderEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendReminderEmail(ctx, realmName, userID, paramKV...)
}

func (c *authorizationComponentMW) ResetSmsCounter(ctx context.Context, realmName string, userID string) error {
	var action = MGMTResetSmsCounter.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetSmsCounter(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var action = MGMTGetCredentialsForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.CredentialRepresentation{}, err
	}

	return c.next.GetCredentialsForUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = MGMTDeleteCredentialsForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
}

func (c *authorizationComponentMW) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var action = MGMTGetRoles.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetRoles(ctx, realmName)
}

func (c *authorizationComponentMW) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var action = MGMTGetRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RoleRepresentation{}, err
	}

	return c.next.GetRole(ctx, realmName, roleID)
}

func (c *authorizationComponentMW) GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error) {
	var action = MGMTGetGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetGroups(ctx, realmName)
}

func (c *authorizationComponentMW) CreateGroup(ctx context.Context, realmName string, group api.GroupRepresentation) (string, error) {
	var action = MGMTCreateGroup.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateGroup(ctx, realmName, group)
}

func (c *authorizationComponentMW) DeleteGroup(ctx context.Context, realmName string, groupID string) error {
	var action = MGMTDeleteGroup.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.DeleteGroup(ctx, realmName, groupID)
}

func (c *authorizationComponentMW) GetAuthorizations(ctx context.Context, realmName string, groupID string) (api.AuthorizationsRepresentation, error) {
	var action = MGMTGetAuthorizations.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return api.AuthorizationsRepresentation{}, err
	}

	return c.next.GetAuthorizations(ctx, realmName, groupID)
}

func (c *authorizationComponentMW) UpdateAuthorizations(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error {
	var action = MGMTUpdateAuthorizations.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.UpdateAuthorizations(ctx, realmName, groupID, group)
}

func (c *authorizationComponentMW) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var action = MGMTGetClientRoles.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRoles(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var action = MGMTCreateClientRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateClientRole(ctx, realmName, clientID, role)
}

func (c *authorizationComponentMW) GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error) {
	var action = MGMTGetRealmCustomConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmCustomConfiguration{}, err
	}

	return c.next.GetRealmCustomConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) UpdateRealmCustomConfiguration(ctx context.Context, realmName string, customConfig api.RealmCustomConfiguration) error {
	var action = MGMTUpdateRealmCustomConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
}

func (c *authorizationComponentMW) GetRealmBackOfficeConfiguration(ctx context.Context, realmName string, groupName string) (api.BackOfficeConfiguration, error) {
	var action = MGMTGetRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, groupName); err != nil {
		return api.BackOfficeConfiguration{}, err
	}

	return c.next.GetRealmBackOfficeConfiguration(ctx, realmName, groupName)
}

func (c *authorizationComponentMW) UpdateRealmBackOfficeConfiguration(ctx context.Context, realmName string, groupName string, config api.BackOfficeConfiguration) error {
	var action = MGMTUpdateRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, groupName); err != nil {
		return err
	}

	return c.next.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupName, config)
}

func (c *authorizationComponentMW) GetUserRealmBackOfficeConfiguration(ctx context.Context, realmName string) (api.BackOfficeConfiguration, error) {
	var action = MGMTGetUserRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.BackOfficeConfiguration{}, err
	}

	return c.next.GetUserRealmBackOfficeConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) CreateShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error {
	var action = MGMTCreateShadowUser.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.CreateShadowUser(ctx, realmName, userID, provider, fedID)
}
