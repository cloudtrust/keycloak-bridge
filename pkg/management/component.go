package management

import (
	"context"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	kc "github.com/cloudtrust/keycloak-client"
)

type KeycloakClient interface {
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetClient(accessToken string, realmName, idClient string) (kc.ClientRepresentation, error)
	GetClients(accessToken string, realmName string, paramKV ...string) ([]kc.ClientRepresentation, error)
	DeleteUser(accessToken string, realmName, userID string) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUsers(accessToken string, realmName string, paramKV ...string) ([]kc.UserRepresentation, error)
	CreateUser(accessToken string, realmName string, user kc.UserRepresentation) (string, error)
	GetClientRoleMappings(accessToken string, realmName, userID, clientID string) ([]kc.RoleRepresentation, error)
	AddClientRolesToUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []kc.RoleRepresentation) error
	GetRealmLevelRoleMappings(accessToken string, realmName, userID string) ([]kc.RoleRepresentation, error)
	ResetPassword(accessToken string, realmName string, userID string, cred kc.CredentialRepresentation) error
	SendVerifyEmail(accessToken string, realmName string, userID string, paramKV ...string) error
	GetRoles(accessToken string, realmName string) ([]kc.RoleRepresentation, error)
	GetRole(accessToken string, realmName string, roleID string) (kc.RoleRepresentation, error)
	GetClientRoles(accessToken string, realmName, idClient string) ([]kc.RoleRepresentation, error)
	CreateClientRole(accessToken string, realmName, clientID string, role kc.RoleRepresentation) (string, error)
}

// Component is the event component interface.
type Component interface {
	GetRealm(ctx context.Context, realmName string) (api.RealmRepresentation, error)
	GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error)
	GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error)
	DeleteUser(ctx context.Context, realmName, userID string) error
	GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error
	GetUsers(ctx context.Context, realmName string, paramKV ...string) ([]api.UserRepresentation, error)
	CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error)
	GetClientRoleMappings(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error)
	AddClientRolesToUserRoleMapping(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error
	GetRealmLevelRoleMappings(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error)
	ResetPassword(ctx context.Context, realmName string, userID string) error
	SendVerifyEmail(ctx context.Context, realmName string, userID string) error
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
}

// Component is the management component.
type component struct {
	keycloakClient KeycloakClient
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient) Component {
	return &component{
		keycloakClient: keycloakClient,
	}
}

func (c *component) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	var realmRep api.RealmRepresentation
	realmKc, err := c.keycloakClient.GetRealm(accessToken, realm)

	realmRep.Id = realmKc.Id
	realmRep.KeycloakVersion = realmKc.KeycloakVersion
	realmRep.Realm = realmKc.Realm
	realmRep.DisplayName = realmKc.DisplayName
	realmRep.Enabled = realmKc.Enabled

	return realmRep, err
}

func (c *component) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	var clientRep api.ClientRepresentation
	clientKc, err := c.keycloakClient.GetClient(accessToken, realmName, idClient)

	clientRep.Id = clientKc.Id
	clientRep.Name = clientKc.Name
	clientRep.BaseUrl = clientKc.BaseUrl
	clientRep.ClientId = clientKc.ClientId
	clientRep.Description = clientKc.Description
	clientRep.Enabled = clientKc.Enabled

	return clientRep, err
}

func (c *component) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	clientsKc, err := c.keycloakClient.GetClients(accessToken, realmName)

	if err != nil {
		return nil, err
	}

	var clientsRep []api.ClientRepresentation
	for _, clientKc := range clientsKc {
		var clientRep api.ClientRepresentation
		clientRep.Id = clientKc.Id
		clientRep.Name = clientKc.Name
		clientRep.BaseUrl = clientKc.BaseUrl
		clientRep.ClientId = clientKc.ClientId
		clientRep.Description = clientKc.Description
		clientRep.Enabled = clientKc.Enabled
		clientsRep = append(clientsRep, clientRep)
	}

	return clientsRep, nil
}

func (c *component) CreateUser(ctx context.Context, realm string, user api.UserRepresentation) (string, error) {
	var accessToken = ctx.Value("access_token").(string)

	var userRep kc.UserRepresentation
	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	if user.MobilePhone != nil {
		var attributes = make(map[string][]string)
		attributes["mobilephone"] = []string{*user.MobilePhone}
		userRep.Attributes = &attributes
	}

	locationURL, err := c.keycloakClient.CreateUser(accessToken, realm, userRep)

	if err != nil {
		return "", err
	}

	return locationURL, nil
}

func (c *component) DeleteUser(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value("access_token").(string)

	return c.keycloakClient.DeleteUser(accessToken, realmName, userID)
}

func (c *component) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	var userRep api.UserRepresentation
	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)

	if err != nil {
		return userRep, err
	}

	userRep.Id = userKc.Id
	userRep.Username = userKc.Username
	userRep.Email = userKc.Email
	userRep.Enabled = userKc.Enabled
	userRep.EmailVerified = userKc.EmailVerified
	userRep.FirstName = userKc.FirstName
	userRep.LastName = userKc.LastName

	if userKc.Attributes != nil {
		var m = *userKc.Attributes
		var mobilePhone = m["mobilephone"][0]
		userRep.MobilePhone = &mobilePhone
	}

	return userRep, nil
}

func (c *component) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var accessToken = ctx.Value("access_token").(string)

	var userRep kc.UserRepresentation
	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	if user.MobilePhone != nil {
		var attributes = make(map[string][]string)
		attributes["mobilephone"] = []string{*user.MobilePhone}
		userRep.Attributes = &attributes
	}

	return c.keycloakClient.UpdateUser(accessToken, realmName, userID, userRep)
}

func (c *component) GetUsers(ctx context.Context, realmName string, paramKV ...string) ([]api.UserRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	usersKc, err := c.keycloakClient.GetUsers(accessToken, realmName)

	if err != nil {
		return nil, err
	}

	var usersRep []api.UserRepresentation
	for _, userKc := range usersKc {
		var userRep api.UserRepresentation
		userRep.Id = userKc.Id
		userRep.Username = userKc.Username
		userRep.Email = userKc.Email
		userRep.Enabled = userKc.Enabled
		userRep.EmailVerified = userKc.EmailVerified
		userRep.FirstName = userKc.FirstName
		userRep.LastName = userKc.LastName
	
		if userKc.Attributes != nil {
			var m = *userKc.Attributes
			var mobilePhone = m["mobilephone"][0]
			userRep.MobilePhone = &mobilePhone
		}

		usersRep = append(usersRep, userRep)
	}

	return usersRep, nil
}

func (c *component) GetClientRoleMappings(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	return nil, nil
}

func (c *component) AddClientRolesToUserRoleMapping(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	return nil
}

func (c *component) GetRealmLevelRoleMappings(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	return nil, nil
}

func (c *component) ResetPassword(ctx context.Context, realmName string, userID string) error {
	return nil
}

func (c *component) SendVerifyEmail(ctx context.Context, realmName string, userID string) error {
	return nil
}

func (c *component) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	return nil, nil
}

func (c *component) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	var roleRep api.RoleRepresentation
	roleKc, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)

	roleRep.Id = roleKc.Id
	roleRep.ClientRole = roleKc.ClientRole
	roleRep.Composite = roleKc.Composite
	roleRep.Description = roleKc.Description
	roleRep.Name = roleKc.Name

	return roleRep, err
}

func (c *component) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	rolesKc, err := c.keycloakClient.GetClientRoles(accessToken, realmName, idClient)

	if err != nil {
		return nil, err
	}

	var rolesRep []api.RoleRepresentation
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.Id = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerId = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var accessToken = ctx.Value("access_token").(string)

	var roleRep kc.RoleRepresentation
	roleRep.Id = role.Id
	roleRep.Name = role.Name
	roleRep.ClientRole = role.ClientRole
	roleRep.ContainerId = role.ContainerId
	roleRep.Description = role.Description

	locationURL, err := c.keycloakClient.CreateClientRole(accessToken, realmName, clientID, roleRep)

	if err != nil {
		return "", err
	}

	return locationURL, nil
}
