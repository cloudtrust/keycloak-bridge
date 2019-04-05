package management

import (
	"context"
	"encoding/json"
	"fmt"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/go-kit/kit/log"
)

// Tracking middleware at component level.
type authorisationComponentMW struct {
	authorisations Authorizations
	keycloakClient KeycloakClient
	logger         log.Logger
	next           Component
}

// MakeAuthorisationManagementComponentMW checks authorisation and return an error if the action is not allowed.
func MakeAuthorisationManagementComponentMW(logger log.Logger, keycloakClient KeycloakClient, authorisations Authorizations) func(Component) Component {
	return func(next Component) Component {
		return &authorisationComponentMW{
			authorisations: authorisations,
			keycloakClient: keycloakClient,
			logger:         logger,
			next:           next,
		}
	}
}

// authorisationComponentMW implements Component.
func (c *authorisationComponentMW) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var action = "GetRealm"
	var targetRealm = realm

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RealmRepresentation{}, err
	}

	return c.next.GetRealm(ctx, realm)
}

func (c *authorisationComponentMW) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var action = "GetClient"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.ClientRepresentation{}, err
	}

	return c.next.GetClient(ctx, realmName, idClient)
}

func (c *authorisationComponentMW) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var action = "GetClients"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.ClientRepresentation{}, err
	}

	return c.next.GetClients(ctx, realmName)
}

func (c *authorisationComponentMW) DeleteUser(ctx context.Context, realmName, userID string) error {
	var action = "DeleteUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.DeleteUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var action = "GetUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return api.UserRepresentation{}, err
	}

	return c.next.GetUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var action = "UpdateUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.UpdateUser(ctx, realmName, userID, user)
}

func (c *authorisationComponentMW) GetUsers(ctx context.Context, realmName, group string, paramKV ...string) ([]api.UserRepresentation, error) {
	var action = "GetUsers"
	var targetRealm = realmName

	// TODO Adapt after Get users is changed
	if err := c.checkAuthorisationOnTargetGroup(ctx, action, targetRealm, group); err != nil {
		return []api.UserRepresentation{}, err
	}

	return c.next.GetUsers(ctx, realmName, group, paramKV...)
}

func (c *authorisationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var action = "CreateUser"
	var targetRealm = realmName

	for _, targetGroup := range *user.Groups {
		if err := c.checkAuthorisationOnTargetGroup(ctx, action, targetRealm, targetGroup); err != nil {
			return "", err
		}
	}

	return c.next.CreateUser(ctx, realmName, user)
}

func (c *authorisationComponentMW) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRolesForUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRolesForUser(ctx, realmName, userID, clientID)
}

func (c *authorisationComponentMW) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var action = "AddClientRolesToUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.AddClientRolesToUser(ctx, realmName, userID, clientID, roles)
}

func (c *authorisationComponentMW) GetRealmRolesForUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var action = "GetRealmRolesForUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetRealmRolesForUser(ctx, realmName, userID)
}

func (c *authorisationComponentMW) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error {
	var action = "ResetPassword"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.ResetPassword(ctx, realmName, userID, password)
}

func (c *authorisationComponentMW) SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var action = "SendVerifyEmail"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetUser(ctx, action, targetRealm, userID); err != nil {
		return err
	}

	return c.next.SendVerifyEmail(ctx, realmName, userID, paramKV...)
}

func (c *authorisationComponentMW) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var action = "GetRoles"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return nil, err
	}

	return c.next.GetRoles(ctx, realmName)
}

func (c *authorisationComponentMW) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var action = "GetRole"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return api.RoleRepresentation{}, err
	}

	return c.next.GetRole(ctx, realmName, roleID)
}

func (c *authorisationComponentMW) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var action = "GetClientRoles"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return []api.RoleRepresentation{}, err
	}

	return c.next.GetClientRoles(ctx, realmName, idClient)
}

func (c *authorisationComponentMW) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var action = "CreateClientRole"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetRealm(ctx, action, targetRealm); err != nil {
		return "", err
	}

	return c.next.CreateClientRole(ctx, realmName, clientID, role)
}

func (c *authorisationComponentMW) checkAuthorisationOnTargetUser(ctx context.Context, action, targetRealm, userID string) error {
	var accessToken = ctx.Value("access_token").(string)

	// Retrieve the group of the target user

	var userRep kc.UserRepresentation
	var err error
	if userRep, err = c.keycloakClient.GetUser(accessToken, targetRealm, userID); err != nil {
		return ForbiddenError{}
	}

	if userRep.Groups == nil {
		// No groups assigned, nothing allowed
		return ForbiddenError{}
	}

	for _, targetGroup := range *userRep.Groups {
		if c.checkAuthorisationOnTargetGroup(ctx, action, targetRealm, targetGroup) == nil {
			return nil
		}
	}

	return ForbiddenError{}
}

func (c *authorisationComponentMW) checkAuthorisationOnTargetGroup(ctx context.Context, action, targetRealm, targetGroup string) error {
	var currentRealm = ctx.Value("realm").(string)
	var currentGroups = ctx.Value("groups").([]string)

	for _, group := range currentGroups {
		targetGroupAllowed, wildcard := c.authorisations[currentRealm][group][action]["*"]

		if wildcard {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}

		targetGroupAllowed, nonMasterRealmAllowed := c.authorisations[currentRealm][group][action]["/"]

		if targetRealm != "master" && nonMasterRealmAllowed {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}

		targetGroupAllowed, realmAllowed := c.authorisations[currentRealm][group][action][targetRealm]

		if realmAllowed {
			_, allGroupsAllowed := targetGroupAllowed["*"]
			_, groupAllowed := targetGroupAllowed[targetGroup]

			if allGroupsAllowed || groupAllowed {
				return nil
			}
		}
	}

	return ForbiddenError{}
}

func (c *authorisationComponentMW) checkAuthorisationOnTargetRealm(ctx context.Context, action, targetRealm string) error {
	var currentRealm = ctx.Value("realm").(string)
	var currentGroups = ctx.Value("groups").([]string)

	for _, group := range currentGroups {
		_, wildcard := c.authorisations[currentRealm][group][action]["*"]
		_, nonMasterRealmAllowed := c.authorisations[currentRealm][group][action]["/"]
		_, realmAllowed := c.authorisations[currentRealm][group][action][targetRealm]

		if wildcard || realmAllowed || (targetRealm != "master" && nonMasterRealmAllowed) {
			return nil
		}
	}

	return ForbiddenError{}
}

// ForbiddenError when an operation is not permitted.
type ForbiddenError struct{}

func (e ForbiddenError) Error() string {
	return "ForbiddenError: Operation not permitted."
}

// Authorizations data structure
// 4 dimensions table to express authorisations (realm_of_user, role_of_user, action, target_realm) -> target_group for which the action is allowed
type Authorizations map[string]map[string]map[string]map[string]map[string]struct{}

// LoadAuthorizations loads the authorization YAML into the data structure
// Authorisation matrix is a 4 dimensions table :
//   - realm_of_user
//   - role_of_user
//   - action
//   - target_realm
// -> target_groups for which the action is allowed
//
// Note:
//   '*' can be used to express all target realms
//   '-' can be used to express all non master realms
//   '*' can be used to express all target groups are allowed
func LoadAuthorizations(jsonAuthz string) (Authorizations, error) {
	if jsonAuthz == "" {
		return nil, fmt.Errorf("JSON structure expected.")
	}
	var authz = make(Authorizations)

	if err := json.Unmarshal([]byte(jsonAuthz), &authz); err != nil {
		return nil, err
	}

	return authz, nil
}
