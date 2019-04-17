package management

import (
	"context"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/go-kit/kit/log"
)

// Tracking middleware at component level.
type authorisationComponentMW struct {
	authManager security.AuthorizationManager
	logger      log.Logger
	next        Component
}

// MakeAuthorisationManagementComponentMW checks authorisation and return an error if the action is not allowed.
func MakeAuthorisationManagementComponentMW(logger log.Logger, keycloakClient KeycloakClient, authorisationManager security.AuthorizationManager) func(Component) Component {
	return func(next Component) Component {
		return &authorisationComponentMW{
			authManager: authorisationManager,
			logger:      logger,
			next:        next,
		}
	}
}

// authorisationComponentMW implements Component.
func (c *authorisationComponentMW) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var action = "GetRealms"
	var targetRealm = "*" // For this method, there is no target realm, so we use the wildcard to express there is no constraints.

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RealmRepresentation{}, err
	}

	return c.next.GetRealms(ctx)
}

func (c *authorisationComponentMW) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var action = "GetRealm"
	var targetRealm = realm

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmRepresentation{}, err
	}

	return c.next.GetRealm(ctx, realm)
}

func (c *authorisationComponentMW) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var action = "GetClient"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.ClientRepresentation{}, err
	}

	return c.next.GetClient(ctx, realmName, idClient)
}

func (c *authorisationComponentMW) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var action = "GetClients"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ClientRepresentation{}, err
	}

	return c.next.GetClients(ctx, realmName)
}

func (c *authorisationComponentMW) DeleteUser(ctx context.Context, realmName, userID string) error {
	var action = "DeleteUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var action = "GetUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var action = "UpdateUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorisationComponentMW) GetUsers(ctx context.Context, realmName, group string, paramKV ...string) ([]api.UserRepresentation, error) {
	var action = "GetUsers"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetGroup(ctx, action, targetRealm, group); err != nil {
		return []api.UserRepresentation{}, err
	}

	return c.next.GetUsers(ctx, realmName, group, paramKV...)
}

func (c *authorisationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var action = "CreateUser"
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.authManager.CheckAuthorisationOnTargetGroup(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user)
}

func (c *authorisationComponentMW) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var action = "GetUserAccountStatus"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return nil, err
	}

	return c.next.GetUserAccountStatus(ctx, realmName, userID)
}

func (c *authorisationComponentMW) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRolesForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRolesForUser(ctx, realmName, userID, clientID)
}

func (c *authorisationComponentMW) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var action = "AddClientRolesToUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
}

func (c *authorisationComponentMW) GetRealmRolesForUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = "GetRealmRolesForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRealmRolesForUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error {
	var action = "ResetPassword"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetPassword(ctx, realmName, userID, password)
}

func (c *authorisationComponentMW) SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var action = "SendVerifyEmail"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendVerifyEmail(ctx, realmName, userID, paramKV...)
}

func (c *authorisationComponentMW) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var action = "GetCredentialsForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.CredentialRepresentation{}, err
	}

	return c.next.GetCredentialsForUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var action = "DeleteCredentialsForUser"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteCredentialsForUser(ctx, realmName, userID, credentialID)
}

func (c *authorisationComponentMW) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var action = "GetRoles"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetRoles(ctx, realmName)
}

func (c *authorisationComponentMW) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var action = "GetRole"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RoleRepresentation{}, err
	}

	return c.next.GetRole(ctx, realmName, roleID)
}

func (c *authorisationComponentMW) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRoles"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRoles(ctx, realmName, idClient)
}

func (c *authorisationComponentMW) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var action = "CreateClientRole"
	var targetRealm = realmName

	if err := c.authManager.CheckAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateClientRole(ctx, realmName, clientID, role)
}
