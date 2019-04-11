package management

import (
	"context"
	"fmt"
	"time"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/pkg/event"
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
	GetUsers(ctx context.Context, realmName, group string, paramKV ...string) ([]api.UserRepresentation, error)
	CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error)
	GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error)
	AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error
	GetRealmRolesForUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error)
	ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error
	SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
}

// Component is the management component.
type component struct {
	keycloakClient KeycloakClient
	eventDBModule  event.EventsDBModule
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, eventDBModule event.EventsDBModule) Component {
	return &component{
		keycloakClient: keycloakClient,
		eventDBModule:  eventDBModule,
	}
}

func getAgentDetails(ctx context.Context, event map[string]string) map[string]string {

	//retrieve agent username
	event["agent_username"] = ctx.Value("username").(string)
	//retrieve agent user id - not yet implemented
	//event["userId"] = ctx.Value("userId").(string)
	//retrieve agent realm
	event["agent_realm_name"] = ctx.Value("realm").(string)
	return event
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

func (c *component) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var accessToken = ctx.Value("access_token").(string)

	var userRep kc.UserRepresentation
	userRep.Username = user.Username
	userRep.Email = user.Email
	userRep.Enabled = user.Enabled
	userRep.EmailVerified = user.EmailVerified
	userRep.FirstName = user.FirstName
	userRep.LastName = user.LastName

	var attributes = make(map[string][]string)

	if user.MobilePhone != nil {
		attributes["mobilephone"] = []string{*user.MobilePhone}
	}

	if user.Label != nil {
		attributes["label"] = []string{*user.Label}
	}

	if user.Gender != nil {
		attributes["gender"] = []string{*user.Gender}
	}

	if user.BirthDate != nil {
		attributes["birthDate"] = []string{*user.BirthDate}
	}

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	locationURL, err := c.keycloakClient.CreateUser(accessToken, realmName, userRep)

	if err != nil {
		return "", err
	}

	//store the API call into the DB
	var event = make(map[string]string)
	event["ct_event_type"] = "API_ACCOUNT_CREATION"
	event["realm_name"] = realmName
	if user.Id != nil {
		event["user_id"] = *user.Id
	}
	if user.Username != nil {
		event["username"] = *user.Username
	}

	event["origin"] = "back-office"
	time := time.Now().UTC()
	event["audit_time"] = time.Format("2006-01-02 15:04:05.000")
	//retrieve details of the agent
	event = getAgentDetails(ctx, event)

	// the error should be treated
	_ = c.eventDBModule.Store(ctx, event)

	return locationURL, nil
}

func (c *component) DeleteUser(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value("access_token").(string)

	err := c.keycloakClient.DeleteUser(accessToken, realmName, userID)

	if err != nil {
		return err
	}

	//store the API call into the DB
	var event = make(map[string]string)
	event["ct_event_type"] = "API_ACCOUNT_DELETION"
	event["realm_name"] = realmName
	event["user_id"] = userID
	event["origin"] = "back-office"
	time := time.Now().UTC()
	event["audit_time"] = time.Format("2006-01-02 15:04:05.000")

	//retrieve details of the agent
	event = getAgentDetails(ctx, event)

	// the error should be treated
	_ = c.eventDBModule.Store(ctx, event)

	return nil
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

		if m["mobilephone"] != nil {
			var mobilePhone = m["mobilephone"][0]
			userRep.MobilePhone = &mobilePhone
		}

		if m["label"] != nil {
			var label = m["label"][0]
			userRep.Label = &label
		}

		if m["gender"] != nil {
			var gender = m["gender"][0]
			userRep.Gender = &gender
		}

		if m["birthDate"] != nil {
			var birthDate = m["birthDate"][0]
			userRep.BirthDate = &birthDate
		}
	}

	fmt.Println("GET_DETAILS events")

	//store the API call into the DB
	var event = make(map[string]string)
	event["ct_event_type"] = "GET_DETAILS"
	event["realm_name"] = realmName
	event["user_id"] = userID
	if userKc.Username != nil {
		event["username"] = *userKc.Username
	}
	event["origin"] = "back-office"
	time := time.Now().UTC()
	event["audit_time"] = time.Format("2006-01-02 15:04:05.000")
	//retrieve details of the agent

	event = getAgentDetails(ctx, event)

	// the error should be treated
	_ = c.eventDBModule.Store(ctx, event)

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

	var attributes = make(map[string][]string)

	if user.MobilePhone != nil {
		attributes["mobilephone"] = []string{*user.MobilePhone}
	}

	if user.Label != nil {
		attributes["label"] = []string{*user.Label}
	}

	if user.Gender != nil {
		attributes["gender"] = []string{*user.Gender}
	}

	if user.BirthDate != nil {
		attributes["birthDate"] = []string{*user.BirthDate}
	}

	if len(attributes) > 0 {
		userRep.Attributes = &attributes
	}

	err := c.keycloakClient.UpdateUser(accessToken, realmName, userID, userRep)

	if err != nil {
		return err
	}

	//store the API call into the DB in case the user.Enable is present
	if user.Enabled != nil {
		var event = make(map[string]string)

		event["realm_name"] = realmName
		event["user_id"] = userID
		if user.Username != nil {
			event["username"] = *user.Username
		}
		event["origin"] = "back-office"
		time := time.Now().UTC()
		event["audit_time"] = time.Format("2006-01-02 15:04:05.000")
		//retrieve details of the agent
		event = getAgentDetails(ctx, event)

		//add ct_event_type
		if *user.Enabled {
			// UNLOCK_ACCOUNT ct_event_type
			event["ct_event_type"] = "UNLOCK_ACCOUNT"
		} else {
			// LOCK_ACCOUNT ct_event_type
			event["ct_event_type"] = "LOCK_ACCOUNT"
		}
		// the error should be treated
		_ = c.eventDBModule.Store(ctx, event)

	}

	return nil
}

func (c *component) GetUsers(ctx context.Context, realmName string, group string, paramKV ...string) ([]api.UserRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	usersKc, err := c.keycloakClient.GetUsers(accessToken, realmName, paramKV...)

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

			if m["mobilephone"] != nil {
				var mobilePhone = m["mobilephone"][0]
				userRep.MobilePhone = &mobilePhone
			}

			if m["label"] != nil {
				var label = m["label"][0]
				userRep.Label = &label
			}

			if m["gender"] != nil {
				var gender = m["gender"][0]
				userRep.Gender = &gender
			}

			if m["birthDate"] != nil {
				var birthDate = m["birthDate"][0]
				userRep.BirthDate = &birthDate
			}
		}

		usersRep = append(usersRep, userRep)
	}

	return usersRep, nil
}

func (c *component) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	rolesKc, err := c.keycloakClient.GetClientRoleMappings(accessToken, realmName, userID, clientID)

	if err != nil {
		return nil, err
	}

	var rolesRep []api.RoleRepresentation
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.Id = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerId = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var accessToken = ctx.Value("access_token").(string)

	var rolesRep []kc.RoleRepresentation
	for _, role := range roles {
		var roleRep kc.RoleRepresentation
		roleRep.Id = role.Id
		roleRep.Name = role.Name
		roleRep.Composite = role.Composite
		roleRep.ClientRole = role.ClientRole
		roleRep.ContainerId = role.ContainerId
		roleRep.Description = role.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return c.keycloakClient.AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, rolesRep)
}

func (c *component) GetRealmRolesForUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	rolesKc, err := c.keycloakClient.GetRealmLevelRoleMappings(accessToken, realmName, userID)

	if err != nil {
		return nil, err
	}

	var rolesRep []api.RoleRepresentation
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.Id = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerId = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error {
	var accessToken = ctx.Value("access_token").(string)

	var credKc kc.CredentialRepresentation
	var passwordType = "password"
	credKc.Type = &passwordType
	credKc.Value = password.Value

	err := c.keycloakClient.ResetPassword(accessToken, realmName, userID, credKc)

	if err != nil {
		return err
	}

	//store the API call into the DB
	var event = make(map[string]string)
	event["ct_event_type"] = "INIT_PASSWORD"
	event["realm_name"] = realmName
	event["user_id"] = userID
	event["origin"] = "back-office"
	time := time.Now().UTC()
	event["audit_time"] = time.Format("2006-01-02 15:04:05.000")
	//retrieve details of the agent
	event = getAgentDetails(ctx, event)

	// the error should be treated
	_ = c.eventDBModule.Store(ctx, event)

	return nil
}

func (c *component) SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var accessToken = ctx.Value("access_token").(string)

	return c.keycloakClient.SendVerifyEmail(accessToken, realmName, userID, paramKV...)
}

func (c *component) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	rolesKc, err := c.keycloakClient.GetRoles(accessToken, realmName)

	if err != nil {
		return nil, err
	}

	var rolesRep []api.RoleRepresentation
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.Id = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerId = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var accessToken = ctx.Value("access_token").(string)

	var roleRep api.RoleRepresentation
	roleKc, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)

	roleRep.Id = roleKc.Id
	roleRep.Name = roleKc.Name
	roleRep.Composite = roleKc.Composite
	roleRep.ClientRole = roleKc.ClientRole
	roleRep.ContainerId = roleKc.ContainerId
	roleRep.Description = roleKc.Description

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
		roleRep.Composite = roleKc.Composite
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
	roleRep.Composite = role.Composite
	roleRep.ClientRole = role.ClientRole
	roleRep.ContainerId = role.ContainerId
	roleRep.Description = role.Description

	locationURL, err := c.keycloakClient.CreateClientRole(accessToken, realmName, clientID, roleRep)

	if err != nil {
		return "", err
	}

	return locationURL, nil
}
