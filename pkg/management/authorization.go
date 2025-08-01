package management

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	apicommon "github.com/cloudtrust/keycloak-bridge/api/common"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
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
	var action = security.MGMTGetActions.String()

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
	var action = security.MGMTGetRealms.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RealmRepresentation{}, err
	}

	return c.next.GetRealms(ctx)
}

func (c *authorizationComponentMW) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var action = security.MGMTGetRealm.String()
	var targetRealm = realm

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmRepresentation{}, err
	}

	return c.next.GetRealm(ctx, realm)
}

func (c *authorizationComponentMW) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var action = security.MGMTGetClient.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.ClientRepresentation{}, err
	}

	return c.next.GetClient(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var action = security.MGMTGetClients.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ClientRepresentation{}, err
	}

	return c.next.GetClients(ctx, realmName)
}

func (c *authorizationComponentMW) GetRequiredActions(ctx context.Context, realmName string) ([]api.RequiredActionRepresentation, error) {
	var action = security.MGMTGetRequiredActions.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RequiredActionRepresentation{}, err
	}

	return c.next.GetRequiredActions(ctx, realmName)
}

func (c *authorizationComponentMW) DeleteUser(ctx context.Context, realmName, userID string) error {
	var action = security.MGMTDeleteUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var action = security.MGMTGetUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UpdatableUserRepresentation) error {
	var action = security.MGMTUpdateUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorizationComponentMW) LockUser(ctx context.Context, realmName, userID string) error {
	var action = security.MGMTLockUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.LockUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) UnlockUser(ctx context.Context, realmName, userID string) error {
	var action = security.MGMTUnlockUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UnlockUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error) {
	var action = security.MGMTGetUsers.String()
	var targetRealm = realmName

	for _, groupID := range groupIDs {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
			return api.UsersPageRepresentation{}, err
		}
	}

	return c.next.GetUsers(ctx, realmName, groupIDs, paramKV...)
}

func (c *authorizationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation, generateUsername bool,
	generateNameID bool, termsOfUse bool) (string, error) {
	var action = security.MGMTCreateUser.String()
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user, generateUsername, generateNameID, termsOfUse)
}

func (c *authorizationComponentMW) CreateUserInSocialRealm(ctx context.Context, user api.UserRepresentation, generateNameID bool) (string, error) {
	var action = security.MGMTCreateUserInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateUserInSocialRealm(ctx, user, generateNameID)
}

func (c *authorizationComponentMW) GetUserChecks(ctx context.Context, realmName, userID string) ([]api.UserCheck, error) {
	var action = security.MGMTGetUserChecks.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserChecks(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var action = security.MGMTGetUserAccountStatus.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserAccountStatus(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUserAccountStatusByEmail(ctx context.Context, realmName, email string) (api.UserStatus, error) {
	var action = security.MGMTGetUserAccountStatusByEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.UserStatus{}, err
	}

	return c.next.GetUserAccountStatusByEmail(ctx, realmName, email)
}

func (c *authorizationComponentMW) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = security.MGMTGetRolesOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRolesOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) AddRoleToUser(ctx context.Context, realmName, userID string, roleID string) error {
	var action = security.MGMTAddRoleToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddRoleToUser(ctx, realmName, userID, roleID)
}

func (c *authorizationComponentMW) DeleteRoleForUser(ctx context.Context, realmName, userID string, roleID string) error {
	var action = security.MGMTDeleteRoleForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteRoleForUser(ctx, realmName, userID, roleID)
}

func (c *authorizationComponentMW) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var action = security.MGMTGetGroupsOfUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.GroupRepresentation{}, err
	}

	return c.next.GetGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) AddGroupToUser(ctx context.Context, realmName, userID string, groupID string) error {
	var action = security.MGMTSetGroupsToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	action = security.MGMTAssignableGroupsToUser.String()
	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.AddGroupToUser(ctx, realmName, userID, groupID)
}

func (c *authorizationComponentMW) DeleteGroupForUser(ctx context.Context, realmName, userID string, groupID string) error {
	var action = security.MGMTSetGroupsToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	action = security.MGMTAssignableGroupsToUser.String()
	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.DeleteGroupForUser(ctx, realmName, userID, groupID)
}

func (c *authorizationComponentMW) GetAvailableTrustIDGroups(ctx context.Context, realmName string) ([]string, error) {
	var action = security.MGMTGetAvailableTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []string{}, err
	}

	return c.next.GetAvailableTrustIDGroups(ctx, realmName)
}

func (c *authorizationComponentMW) GetTrustIDGroupsOfUser(ctx context.Context, realmName, userID string) ([]string, error) {
	var action = security.MGMTGetTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetTrustIDGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SetTrustIDGroupsToUser(ctx context.Context, realmName, userID string, groupNames []string) error {
	var action = security.MGMTSetTrustIDGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SetTrustIDGroupsToUser(ctx, realmName, userID, groupNames)
}

func (c *authorizationComponentMW) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var action = security.MGMTGetClientRolesForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRolesForUser(ctx, realmName, userID, clientID)
}

func (c *authorizationComponentMW) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var action = security.MGMTAddClientRolesToUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
}

func (c *authorizationComponentMW) DeleteClientRolesFromUser(ctx context.Context, realmName, userID, clientID string, roleID string, roleName string) error {
	var action = security.MGMTDeleteClientRolesFromUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteClientRolesFromUser(ctx, realmName, userID, clientID, roleID, roleName)
}

func (c *authorizationComponentMW) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error) {
	var action = security.MGMTResetPassword.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.ResetPassword(ctx, realmName, userID, password)
}

func (c *authorizationComponentMW) CreateRecoveryCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = security.MGMTCreateRecoveryCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.CreateRecoveryCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) CreateActivationCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = security.MGMTCreateActivationCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.CreateActivationCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error {
	var action = security.MGMTExecuteActionsEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ExecuteActionsEmail(ctx, realmName, userID, actions, paramKV...)
}

func (c *authorizationComponentMW) RevokeAccreditations(ctx context.Context, realmName string, userID string) error {
	var action = security.MGMTRevokeAccreditations.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.RevokeAccreditations(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendSmsCode(ctx context.Context, realmName string, userID string) (string, error) {
	var action = security.MGMTSendSmsCode.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return "", err
	}

	return c.next.SendSmsCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) SendOnboardingEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, paramKV ...string) error {
	var action = security.MGMTSendOnboardingEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendOnboardingEmail(ctx, realmName, userID, customerRealm, reminder, paramKV...)
}

func (c *authorizationComponentMW) SendOnboardingEmailInSocialRealm(ctx context.Context, userID string, customerRealm string, reminder bool, paramKV ...string) error {
	var action = security.MGMTSendOnboardingEmailInSocialRealm.String()

	// For this method, there is no target realm provided
	// as parameter, so we pick the current realm of the user.
	var targetRealm = ctx.Value(cs.CtContextRealm).(string)

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.SendOnboardingEmailInSocialRealm(ctx, userID, customerRealm, reminder, paramKV...)
}

/* REMOVE_THIS_3901 : start */
func (c *authorizationComponentMW) SendMigrationEmail(ctx context.Context, realmName string, userID string, customerRealm string, reminder bool, lifespan *int) error {
	// let's use SendOnboardingEmail action
	var action = security.MGMTSendOnboardingEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendMigrationEmail(ctx, realmName, userID, customerRealm, reminder, lifespan)
}

/* REMOVE_THIS_3901 : end */

func (c *authorizationComponentMW) SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var action = security.MGMTSendReminderEmail.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendReminderEmail(ctx, realmName, userID, paramKV...)
}

func (c *authorizationComponentMW) ResetSmsCounter(ctx context.Context, realmName string, userID string) error {
	var action = security.MGMTResetSmsCounter.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetSmsCounter(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var action = security.MGMTGetCredentialsForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.CredentialRepresentation{}, err
	}

	return c.next.GetCredentialsForUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = security.MGMTDeleteCredentialsForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
}

func (c *authorizationComponentMW) ResetCredentialFailuresForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = security.MGMTResetCredentialFailuresForUser.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetCredentialFailuresForUser(ctx, realmName, userID, credentialID)
}

func (c *authorizationComponentMW) ClearUserLoginFailures(ctx context.Context, realmName, userID string) error {
	var action = security.MGMTClearUserLoginFailures.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ClearUserLoginFailures(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetAttackDetectionStatus(ctx context.Context, realmName, userID string) (api.AttackDetectionStatusRepresentation, error) {
	var action = security.MGMTGetAttackDetectionStatus.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.AttackDetectionStatusRepresentation{}, err
	}

	return c.next.GetAttackDetectionStatus(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var action = security.MGMTGetRoles.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetRoles(ctx, realmName)
}

func (c *authorizationComponentMW) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var action = security.MGMTGetRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RoleRepresentation{}, err
	}

	return c.next.GetRole(ctx, realmName, roleID)
}

func (c *authorizationComponentMW) CreateRole(ctx context.Context, realmName string, role api.RoleRepresentation) (string, error) {
	var action = security.MGMTCreateRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateRole(ctx, realmName, role)
}

func (c *authorizationComponentMW) UpdateRole(ctx context.Context, realmName string, roleID string, role api.RoleRepresentation) error {
	var action = security.MGMTUpdateRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRole(ctx, realmName, roleID, role)
}

func (c *authorizationComponentMW) DeleteRole(ctx context.Context, realmName string, roleID string) error {
	var action = security.MGMTDeleteRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.DeleteRole(ctx, realmName, roleID)
}

func (c *authorizationComponentMW) GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error) {
	var action = security.MGMTGetGroups.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	groups, err := c.next.GetGroups(ctx, realmName)
	if err != nil {
		return nil, err
	}

	filteredGroups := []api.GroupRepresentation{}
	for _, group := range groups {
		if c.authManager.CheckAuthorizationOnTargetGroup(ctx, security.MGMTIncludedInGetGroups.String(), realmName, *group.Name) == nil {
			filteredGroups = append(filteredGroups, group)
		}
	}

	return filteredGroups, nil
}

func (c *authorizationComponentMW) CreateGroup(ctx context.Context, realmName string, group api.GroupRepresentation) (string, error) {
	var action = security.MGMTCreateGroup.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateGroup(ctx, realmName, group)
}

func (c *authorizationComponentMW) DeleteGroup(ctx context.Context, realmName string, groupID string) error {
	var action = security.MGMTDeleteGroup.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
		return err
	}

	return c.next.DeleteGroup(ctx, realmName, groupID)
}

func (c *authorizationComponentMW) GetAuthorizations(ctx context.Context, realmName string, groupID string) (api.AuthorizationsRepresentation, error) {
	var action = security.MGMTGetAuthorizations.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return api.AuthorizationsRepresentation{}, err
	}

	return c.next.GetAuthorizations(ctx, realmName, groupID)
}

func (c *authorizationComponentMW) UpdateAuthorizations(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error {
	var action = security.MGMTUpdateAuthorizations.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.UpdateAuthorizations(ctx, realmName, groupID, group)
}

func (c *authorizationComponentMW) AddAuthorization(ctx context.Context, realmName string, groupID string, group api.AuthorizationsRepresentation) error {
	var action = security.MGMTAddAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.AddAuthorization(ctx, realmName, groupID, group)
}

func (c *authorizationComponentMW) GetAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) (api.AuthorizationMessage, error) {
	var action = security.MGMTGetAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return api.AuthorizationMessage{}, err
	}

	return c.next.GetAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, actionReq)
}

func (c *authorizationComponentMW) DeleteAuthorization(ctx context.Context, realmName string, groupID string, targetRealm string, targetGroupID string, actionReq string) error {
	var action = security.MGMTDeleteAuthorization.String()

	if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, realmName, groupID); err != nil {
		return err
	}

	return c.next.DeleteAuthorization(ctx, realmName, groupID, targetRealm, targetGroupID, actionReq)
}

func (c *authorizationComponentMW) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var action = security.MGMTGetClientRoles.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRoles(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var action = security.MGMTCreateClientRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateClientRole(ctx, realmName, clientID, role)
}

func (c *authorizationComponentMW) DeleteClientRole(ctx context.Context, realmName, clientID string, roleID string) error {
	var action = security.MGMTDeleteClientRole.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.DeleteClientRole(ctx, realmName, clientID, roleID)
}

func (c *authorizationComponentMW) GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error) {
	var action = security.MGMTGetRealmCustomConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmCustomConfiguration{}, err
	}

	return c.next.GetRealmCustomConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) UpdateRealmCustomConfiguration(ctx context.Context, realmName string, customConfig api.RealmCustomConfiguration) error {
	var action = security.MGMTUpdateRealmCustomConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
}

func (c *authorizationComponentMW) GetRealmAdminConfiguration(ctx context.Context, realmName string) (api.RealmAdminConfiguration, error) {
	var action = security.MGMTGetRealmAdminConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmAdminConfiguration{}, err
	}

	return c.next.GetRealmAdminConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) UpdateRealmAdminConfiguration(ctx context.Context, realmName string, adminConfig api.RealmAdminConfiguration) error {
	var action = security.MGMTUpdateRealmAdminConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRealmAdminConfiguration(ctx, realmName, adminConfig)
}

func (c *authorizationComponentMW) GetRealmUserProfile(ctx context.Context, realmName string) (apicommon.ProfileRepresentation, error) {
	var action = security.MGMTGetRealmUserProfile.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return apicommon.ProfileRepresentation{}, err
	}

	return c.next.GetRealmUserProfile(ctx, realmName)
}

func (c *authorizationComponentMW) GetRealmBackOfficeConfiguration(ctx context.Context, realmName string, groupName string) (api.BackOfficeConfiguration, error) {
	var action = security.MGMTGetRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, groupName); err != nil {
		return api.BackOfficeConfiguration{}, err
	}

	return c.next.GetRealmBackOfficeConfiguration(ctx, realmName, groupName)
}

func (c *authorizationComponentMW) UpdateRealmBackOfficeConfiguration(ctx context.Context, realmName string, groupName string, config api.BackOfficeConfiguration) error {
	var action = security.MGMTUpdateRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetGroup(ctx, action, targetRealm, groupName); err != nil {
		return err
	}

	return c.next.UpdateRealmBackOfficeConfiguration(ctx, realmName, groupName, config)
}

func (c *authorizationComponentMW) GetUserRealmBackOfficeConfiguration(ctx context.Context, realmName string) (api.BackOfficeConfiguration, error) {
	var action = security.MGMTGetUserRealmBackOfficeConfiguration.String()
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.BackOfficeConfiguration{}, err
	}

	return c.next.GetUserRealmBackOfficeConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) GetFederatedIdentities(ctx context.Context, realmName string, userID string) ([]api.FederatedIdentityRepresentation, error) {
	var action = security.MGMTGetFederatedIdentities.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetFederatedIdentities(ctx, realmName, userID)
}

func (c *authorizationComponentMW) LinkShadowUser(ctx context.Context, realmName string, userID string, provider string, fedID api.FederatedIdentityRepresentation) error {
	var action = security.MGMTLinkShadowUser.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.LinkShadowUser(ctx, realmName, userID, provider, fedID)
}

func (c *authorizationComponentMW) UnlinkShadowUser(ctx context.Context, realmName string, userID string, provider string) error {
	var action = security.MGMTUnlinkShadowUser.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UnlinkShadowUser(ctx, realmName, userID, provider)
}

func (c *authorizationComponentMW) GetIdentityProviders(ctx context.Context, realmName string) ([]api.IdentityProviderRepresentation, error) {
	var action = security.MGMTGetIdentityProviders.String()
	var targetRealm = realmName
	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.IdentityProviderRepresentation{}, err
	}

	return c.next.GetIdentityProviders(ctx, realmName)
}
