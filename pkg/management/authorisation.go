package management

import (
	"context"
	"fmt"
	"io/ioutil"
	"encoding/json"

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

func (c *authorisationComponentMW) GetUsers(ctx context.Context, realmName string, paramKV ...string) ([]api.UserRepresentation, error) {
	var action = "GetUsers"
	var targetRealm = realmName
 
	// TODO Adapt after Get users is changed
	if err := c.checkAuthorisationOnTargetGroup(ctx, action, targetRealm, "*"); err != nil {
		return []api.UserRepresentation{}, err
	}

	return c.next.GetUsers(ctx, realmName, paramKV...)
}

func (c *authorisationComponentMW) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var action = "CreateUser"
	var targetRealm = realmName

	if err := c.checkAuthorisationOnTargetGroup(ctx, action, targetRealm, *user.Group); err != nil {
		return "", err
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
	var currentRealm = ctx.Value("realm").(string)
	var currentGroup = ctx.Value("group").(string)
	var accessToken = ctx.Value("access_token").(string)

	_, okWildcard := c.authorisations[currentRealm][currentGroup][action][targetRealm]["*"]

	if okWildcard {
		// Allowed to perform action on everyone
		return nil
	}

	// Check if allowed to perform this action on this specific group of user

	var userRep kc.UserRepresentation
	var err error
	if userRep, err = c.keycloakClient.GetUser(accessToken, targetRealm, userID); err != nil {
		// TODO be more precise could be due to a technical error maybe something else that forbidden
		return ForbiddenError{}
	}

	var targetGroups = *userRep.Groups

	if len(targetGroups) <= 0 {
		c.logger.Log("Operation not allowed", fmt.Sprintf("no group assigned to user %s", userID))
		return ForbiddenError{}
	}

	if len(targetGroups) > 1 {
		c.logger.Log("Warning", "Only first group is took into account for authorisation evaluation")
	}

	var targetGroup = targetGroups[0]

	_, ok := c.authorisations[currentRealm][currentGroup][action][targetRealm][targetGroup]

	if !ok {
		return ForbiddenError{}
	}

	return nil
}

func (c *authorisationComponentMW) checkAuthorisationOnTargetGroup(ctx context.Context, action, targetRealm, targetGroup string) error {
	var currentRealm = ctx.Value("realm").(string)
	var currentGroup = ctx.Value("group").(string)

	_, okWildcard := c.authorisations[currentRealm][currentGroup][action][targetRealm]["*"]

	if okWildcard {
		// Allowed to perform action on everyone
		return nil
	}

	// Check if allowed to perform this action on this specific group of user
	_, ok := c.authorisations[currentRealm][currentGroup][action][targetRealm][targetGroup]

	if !ok {
		return ForbiddenError{}
	}

	return nil
}

func (c *authorisationComponentMW) checkAuthorisationOnTargetRealm(ctx context.Context, action, targetRealm string) error {
	var currentRealm = ctx.Value("realm").(string)
	var currentGroup = ctx.Value("groups").(string)

	_, ok := c.authorisations[currentRealm][currentGroup][action][targetRealm]

	if !ok {
		return ForbiddenError{}
	}

	return nil
}

// ForbiddenError when an operation is not permitted.
type ForbiddenError struct {}

func (e ForbiddenError) Error() string {
	return "ForbiddenError: Operation not permitted."
}

// Authorizations data structure 
// 4 dimensions table to express authorisations (realm_of_user, role_of_user, action, target_realm) -> target_group for which the action is allowed
type Authorizations map[string]map[string]map[string]map[string]map[string]struct{}

// LoadAuthorizations loads the authorization YAML into the data structure
func LoadAuthorizations(authorizationConfigPath string) (Authorizations, error) {
	jsonAuthz, err := ioutil.ReadFile(authorizationConfigPath)

	if err != nil {
		return nil, err
	}

	var authz = make(Authorizations)

	if err = json.Unmarshal(jsonAuthz, &authz); err != nil {
		return nil ,err
	}

	return authz, nil
}