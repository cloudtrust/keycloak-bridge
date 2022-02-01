package management

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
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
	MGMTLockUser                            = newAction("MGMT_LockUser", security.ScopeGroup)
	MGMTUnlockUser                          = newAction("MGMT_UnlockUser", security.ScopeGroup)
	MGMTGetUsers                            = newAction("MGMT_GetUsers", security.ScopeGroup)
	MGMTCreateUser                          = newAction("MGMT_CreateUser", security.ScopeGroup)
	MGMTCreateUserInSocialRealm             = newAction("MGMT_CreateUserInSocialRealm", security.ScopeRealm)
	MGMTGetUserChecks                       = newAction("MGMT_GetUserChecks", security.ScopeGroup)
	MGMTGetUserAccountStatus                = newAction("MGMT_GetUserAccountStatus", security.ScopeGroup)
	MGMTGetUserAccountStatusByEmail         = newAction("MGMT_GetUserAccountStatusByEmail", security.ScopeRealm)
	MGMTGetRolesOfUser                      = newAction("MGMT_GetRolesOfUser", security.ScopeGroup)
	MGMTAddRoleToUser                       = newAction("MGMT_AddRoleToUser", security.ScopeGroup)
	MGMTDeleteRoleForUser                   = newAction("MGMT_DeleteRoleForUser", security.ScopeGroup)
	MGMTGetGroupsOfUser                     = newAction("MGMT_GetGroupsOfUser", security.ScopeGroup)
	MGMTSetGroupsToUser                     = newAction("MGMT_SetGroupsToUser", security.ScopeGroup)
	MGMTAssignableGroupsToUser              = newAction("MGMT_AssignableGroupsToUser", security.ScopeGroup)
	MGMTGetAvailableTrustIDGroups           = newAction("MGMT_GetAvailableTrustIDGroups", security.ScopeRealm)
	MGMTGetTrustIDGroups                    = newAction("MGMT_GetTrustIDGroups", security.ScopeGroup)
	MGMTSetTrustIDGroups                    = newAction("MGMT_SetTrustIDGroups", security.ScopeGroup)
	MGMTGetClientRolesForUser               = newAction("MGMT_GetClientRolesForUser", security.ScopeGroup)
	MGMTAddClientRolesToUser                = newAction("MGMT_AddClientRolesToUser", security.ScopeGroup)
	MGMTResetPassword                       = newAction("MGMT_ResetPassword", security.ScopeGroup)
	MGMTExecuteActionsEmail                 = newAction("MGMT_ExecuteActionsEmail", security.ScopeGroup)
	MGMTRevokeAccreditations                = newAction("ACCR_RevokeAccreditations", security.ScopeGroup)
	MGMTSendSmsCode                         = newAction("MGMT_SendSmsCode", security.ScopeGroup)
	MGMTSendOnboardingEmail                 = newAction("MGMT_SendOnboardingEmail", security.ScopeGroup)
	MGMTSendOnboardingEmailInSocialRealm    = newAction("MGMT_SendOnboardingEmailInSocialRealm", security.ScopeRealm)
	MGMTSendReminderEmail                   = newAction("MGMT_SendReminderEmail", security.ScopeGroup)
	MGMTResetSmsCounter                     = newAction("MGMT_ResetSmsCounter", security.ScopeGroup)
	MGMTCreateRecoveryCode                  = newAction("MGMT_CreateRecoveryCode", security.ScopeGroup)
	MGMTCreateActivationCode                = newAction("MGMT_CreateActivationCode", security.ScopeGroup)
	MGMTGetCredentialsForUser               = newAction("MGMT_GetCredentialsForUser", security.ScopeGroup)
	MGMTDeleteCredentialsForUser            = newAction("MGMT_DeleteCredentialsForUser", security.ScopeGroup)
	MGMTResetCredentialFailuresForUser      = newAction("MGMT_ResetCredentialFailuresForUser", security.ScopeGroup)
	MGMTClearUserLoginFailures              = newAction("MGMT_ClearUserLoginFailures", security.ScopeGroup)
	MGMTGetAttackDetectionStatus            = newAction("MGMT_GetAttackDetectionStatus", security.ScopeGroup)
	MGMTGetRoles                            = newAction("MGMT_GetRoles", security.ScopeRealm)
	MGMTGetRole                             = newAction("MGMT_GetRole", security.ScopeRealm)
	MGMTCreateRole                          = newAction("MGMT_CreateRole", security.ScopeRealm)
	MGMTUpdateRole                          = newAction("MGMT_UpdateRole", security.ScopeRealm)
	MGMTDeleteRole                          = newAction("MGMT_DeleteRole", security.ScopeRealm)
	MGMTGetGroups                           = newAction("MGMT_GetGroups", security.ScopeRealm)
	MGMTCreateGroup                         = newAction("MGMT_CreateGroup", security.ScopeRealm)
	MGMTDeleteGroup                         = newAction("MGMT_DeleteGroup", security.ScopeGroup)
	MGMTGetAuthorizations                   = newAction("MGMT_GetAuthorizations", security.ScopeGroup)
	MGMTUpdateAuthorizations                = newAction("MGMT_UpdateAuthorizations", security.ScopeGroup)
	MGMTAddAuthorization                    = newAction("MGMT_AddAuthorization", security.ScopeGroup)
	MGMTGetAuthorization                    = newAction("MGMT_GetAuthorization", security.ScopeGroup)
	MGMTDeleteAuthorization                 = newAction("MGMT_DeleteAuthorization", security.ScopeGroup)
	MGMTGetClientRoles                      = newAction("MGMT_GetClientRoles", security.ScopeRealm)
	MGMTCreateClientRole                    = newAction("MGMT_CreateClientRole", security.ScopeRealm)
	MGMTGetRealmCustomConfiguration         = newAction("MGMT_GetRealmCustomConfiguration", security.ScopeRealm)
	MGMTUpdateRealmCustomConfiguration      = newAction("MGMT_UpdateRealmCustomConfiguration", security.ScopeRealm)
	MGMTGetRealmAdminConfiguration          = newAction("MGMT_GetRealmAdminConfiguration", security.ScopeRealm)
	MGMTUpdateRealmAdminConfiguration       = newAction("MGMT_UpdateRealmAdminConfiguration", security.ScopeRealm)
	MGMTGetRealmBackOfficeConfiguration     = newAction("MGMT_GetRealmBackOfficeConfiguration", security.ScopeGroup)
	MGMTUpdateRealmBackOfficeConfiguration  = newAction("MGMT_UpdateRealmBackOfficeConfiguration", security.ScopeGroup)
	MGMTGetUserRealmBackOfficeConfiguration = newAction("MGMT_GetUserRealmBackOfficeConfiguration", security.ScopeRealm)
	MGMTLinkShadowUser                      = newAction("MGMT_LinkShadowUser", security.ScopeRealm)
)

// Tracking middleware at component level.
type authorizationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// GetActions returns available actions
func GetActions() []security.Action {
	return actions
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

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ActionRepresentation{}, err
	}

	return c.next.GetActions(ctx)
}

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var action = MGMTGetRealms.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

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

func (c *authorizationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UpdatableUserRepresentation) error {
	var action = MGMTUpdateUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorizationComponentMW) LockUser(ctx context.Context, realmName, userID string) error {
	var action = MGMTLockUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.LockUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) UnlockUser(ctx context.Context, realmName, userID string) error {
	var action = MGMTUnlockUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UnlockUser(ctx, realmName, userID)
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

func (c *authorizationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation, generateUsername bool, generateNameID bool, termsOfUse bool) (string, error) {
	var action = MGMTCreateUser.String()
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user, generateUsername, generateNameID, termsOfUse)
}

func (c *authorizationComponentMW) CreateUserInSocialRealm(ctx context.Context, user api.UserRepresentation, generateNameID bool) (string, error) {
	var action = MGMTCreateUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateUserInSocialRealm(ctx, user, generateNameID)
}

func (c *authorizationComponentMW) GetUserChecks(ctx context.Context, realmName, userID string) ([]api.UserCheck, error) {
	var action = MGMTGetUserChecks.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserChecks(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var action = MGMTGetUserAccountStatus.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserAccountStatus(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUserAccountStatusByEmail(ctx context.Context, realmName, email string) (api.UserStatus, error) {
	var action = MGMTGetUserAccountStatusByEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.UserStatus{}, err
	}

	return c.next.GetUserAccountStatusByEmail(ctx, realmName, email)
}

func (c *authorizationComponentMW) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = MGMTGetRolesOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRolesOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) AddRoleToUser(ctx context.Context, realmName, userID string, roleID string) error {
	var action = MGMTAddRoleToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddRoleToUser(ctx, realmName, userID, roleID)
}

func (c *authorizationComponentMW) DeleteRoleForUser(ctx context.Context, realmName, userID string, roleID string) error {
	var action = MGMTDeleteRoleForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteRoleForUser(ctx, realmName, userID, roleID)
}

func (c *authorizationComponentMW) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var action = MGMTGetGroupsOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.GroupRepresentation{}, err
	}

	return c.next.GetGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) AddGroupToUser(ctx context.Context, realmName, userID string, groupID string) error {
	var action = MGMTSetGroupsToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	action = MGMTAssignableGroupsToUser.String()
	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.AddGroupToUser(ctx, realmName, userID, groupID)
}

func (c *authorizationComponentMW) DeleteGroupForUser(ctx context.Context, realmName, userID string, groupID string) error {
	var action = MGMTSetGroupsToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	action = MGMTAssignableGroupsToUser.String()
	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.DeleteGroupForUser(ctx, realmName, userID, groupID)
}

func (c *authorizationComponentMW) GetAvailableTrustIDGroups(ctx context.Context, realmName string) ([]string, error) {
	var action = MGMTGetAvailableTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []string{}, err
	}

	return c.next.GetAvailableTrustIDGroups(ctx, realmName)
}

func (c *authorizationComponentMW) GetTrustIDGroupsOfUser(ctx context.Context, realmName, userID string) ([]string, error) {
	var action = MGMTGetTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetTrustIDGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SetTrustIDGroupsToUser(ctx context.Context, realmName, userID string, groupNames []string) error {
	var action = MGMTSetTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SetTrustIDGroupsToUser(ctx, realmName, userID, groupNames)
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

func (c *authorizationComponentMW) CreateActivationCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = MGMTCreateActivationCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.CreateActivationCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error {
	var action = MGMTExecuteActionsEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ExecuteActionsEmail(ctx, realmName, userID, actions, paramKV...)
}

func (c *authorizationComponentMW) RevokeAccreditations(ctx context.Context, realmName string, userID string) error {
	var action = MGMTRevokeAccreditations.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.RevokeAccreditations(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = MGMTSendSmsCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.SendSmsCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error {
	var action = MGMTSendOnboardingEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendOnboardingEmail(ctx, realmName, userID, customerRealm, reminder, lifespan)
}

func (c *authorizationComponentMW) SendOnboardingEmailInSocialRealm(ctx context.Context, userID string, customerRealm string, reminder bool, lifespan *int) error {
	var action = MGMTSendOnboardingEmailInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, reminder, lifespan)
}

/* REMOVE_THIS_3901 : start */
func (c *authorizationComponentMW) SendMigrationEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error {
	// let's use SendOnboardingEmail action
	var action = MGMTSendOnboardingEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendMigrationEmail(ctx, realmName, userID, customerRealm, reminder, lifespan)
}

/* REMOVE_THIS_3901 : end */

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

func (c *authorizationComponentMW) ResetCredentialFailuresForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = MGMTResetCredentialFailuresForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
}

func (c *authorizationComponentMW) ClearUserLoginFailures(ctx context.Context, realmName, userID string) error {
	var action = MGMTClearUserLoginFailures.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ClearUserLoginFailures(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetAttackDetectionStatus(ctx context.Context, realmName, userID string) (api.AttackDetectionStatusRepresentation, error) {
	var action = MGMTGetAttackDetectionStatus.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.AttackDetectionStatusRepresentation{}, err
	}

	return c.next.GetAttackDetectionStatus(ctx, realmName, userID)
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

func (c *authorizationComponentMW) CreateRole(ctx context.Context, realmName string, role api.RoleRepresentation) (string, error) {
	var action = MGMTCreateRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateRole(ctx, realmName, role)
}

func (c *authorizationComponentMW) UpdateRole(ctx context.Context, realmName string, roleID string, role api.RoleRepresentation) error {
	var action = MGMTUpdateRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRole(ctx, realmName, roleID, role)
}

func (c *authorizationComponentMW) DeleteRole(ctx context.Context, realmName string, roleID string) error {
	var action = MGMTDeleteRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.DeleteRole(ctx, realmName, roleID)
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

func (c *authorizationComponentMW) AddAuthorization(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error {
	var action = MGMTAddAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.AddAuthorization(ctx, realmName, groupID, group)
}

func (c *authorizationComponentMW) GetAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) (api.AuthorizationMessage, error) {
	var action = MGMTGetAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return api.AuthorizationMessage{}, err
	}

	return c.next.GetAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, actionReq)
}

func (c *authorizationComponentMW) DeleteAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) error {
	var action = MGMTDeleteAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.DeleteAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, actionReq)
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

func (c *authorizationComponentMW) GetRealmAdminConfiguration(ctx context.Context, realmName string) (api.RealmAdminConfiguration, error) {
	var action = MGMTGetRealmAdminConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmAdminConfiguration{}, err
	}

	return c.next.GetRealmAdminConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) UpdateRealmAdminConfiguration(ctx context.Context, realmName string, adminConfig api.RealmAdminConfiguration) error {
	var action = MGMTUpdateRealmAdminConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
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

func (c *authorizationComponentMW) LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error {
	var action = MGMTLinkShadowUser.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.LinkShadowUser(ctx, realmName, userID, provider, fedID)
}
