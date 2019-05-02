package management

import (
	"context"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/go-kit/kit/log"
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

// authorizationComponentMW implements Component.
func (c *authorizationComponentMW) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var action = "GetRealms"
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RealmRepresentation{}, err
	}

	return c.next.GetRealms(ctx)
}

func (c *authorizationComponentMW) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var action = "GetRealm"
	var targetRealm = realm

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmRepresentation{}, err
	}

	return c.next.GetRealm(ctx, realm)
}

func (c *authorizationComponentMW) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var action = "GetClient"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.ClientRepresentation{}, err
	}

	return c.next.GetClient(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var action = "GetClients"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ClientRepresentation{}, err
	}

	return c.next.GetClients(ctx, realmName)
}

func (c *authorizationComponentMW) DeleteUser(ctx context.Context, realmName, userID string) error {
	var action = "DeleteUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var action = "GetUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var action = "UpdateUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorizationComponentMW) GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) ([]api.UserRepresentation, error) {
	var action = "GetUsers"
	var targetRealm = realmName

	for _, groupID := range groupIDs {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, groupID); err != nil {
			return []api.UserRepresentation{}, err
		}
	}	

	return c.next.GetUsers(ctx, realmName, groupIDs, paramKV...)
}

func (c *authorizationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var action = "CreateUser"
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.authManager.CheckAuthorizationOnTargetGroupID(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user)
}

func (c *authorizationComponentMW) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var action = "GetUserAccountStatus"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserAccountStatus(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = "GetRolesOfUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRolesOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var action = "GetGroupsOfUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.GroupRepresentation{}, err
	}

	return c.next.GetGroupsOfUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRolesForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRolesForUser(ctx, realmName, userID, clientID)
}

func (c *authorizationComponentMW) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var action = "AddClientRolesToUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
}

func (c *authorizationComponentMW) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error {
	var action = "ResetPassword"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetPassword(ctx, realmName, userID, password)
}

func (c *authorizationComponentMW) SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var action = "SendVerifyEmail"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendVerifyEmail(ctx, realmName, userID, paramKV...)
}

func (c *authorizationComponentMW) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []string, paramKV ...string) error {
	var action = "ExecuteActionsEmail"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ExecuteActionsEmail(ctx, realmName, userID, actions, paramKV...)
}

func (c *authorizationComponentMW) SendNewEnrolmentCode(ctx context.Context, realmName string, userID string) error {
	var action = "SendNewEnrolmentCode"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendNewEnrolmentCode(ctx, realmName, userID)
}

func (c *authorizationComponentMW) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var action = "GetCredentialsForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.CredentialRepresentation{}, err
	}

	return c.next.GetCredentialsForUser(ctx, realmName, userID)
}

func (c *authorizationComponentMW) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = "DeleteCredentialsForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
}

func (c *authorizationComponentMW) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var action = "GetRoles"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetRoles(ctx, realmName)
}

func (c *authorizationComponentMW) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var action = "GetRole"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RoleRepresentation{}, err
	}

	return c.next.GetRole(ctx, realmName, roleID)
}

func (c *authorizationComponentMW) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRoles"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRoles(ctx, realmName, idClient)
}

func (c *authorizationComponentMW) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var action = "CreateClientRole"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateClientRole(ctx, realmName, clientID, role)
}

func (c *authorizationComponentMW) GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error) {
	var action = "GetRealmCustomConfiguration"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmCustomConfiguration{}, err
	}

	return c.next.GetRealmCustomConfiguration(ctx, realmName)
}

func (c *authorizationComponentMW) UpdateRealmCustomConfiguration(ctx context.Context, realmName string, customConfig api.RealmCustomConfiguration) error {
	var action = "UpdateRealmCustomConfiguration"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorizationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return err
	}

	return c.next.UpdateRealmCustomConfiguration(ctx, realmName, customConfig)
}
