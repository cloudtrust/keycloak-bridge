package management

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	kc "github.com/cloudtrust/keycloak-client"
	"github.com/pkg/errors"
)

const (
	initPasswordAction = "sms-password-set"
)

// KeycloakClient are methods from keycloak-client used by this component
type KeycloakClient interface {
	GetRealms(accessToken string) ([]kc.RealmRepresentation, error)
	GetRealm(accessToken string, realmName string) (kc.RealmRepresentation, error)
	GetClient(accessToken string, realmName, idClient string) (kc.ClientRepresentation, error)
	GetClients(accessToken string, realmName string, paramKV ...string) ([]kc.ClientRepresentation, error)
	DeleteUser(accessToken string, realmName, userID string) error
	GetUser(accessToken string, realmName, userID string) (kc.UserRepresentation, error)
	GetGroupsOfUser(accessToken string, realmName, userID string) ([]kc.GroupRepresentation, error)
	UpdateUser(accessToken string, realmName, userID string, user kc.UserRepresentation) error
	GetUsers(accessToken string, reqRealmName, targetRealmName string, paramKV ...string) (kc.UsersPageRepresentation, error)
	CreateUser(accessToken string, realmName string, targetRealmName string, user kc.UserRepresentation) (string, error)
	GetClientRoleMappings(accessToken string, realmName, userID, clientID string) ([]kc.RoleRepresentation, error)
	AddClientRolesToUserRoleMapping(accessToken string, realmName, userID, clientID string, roles []kc.RoleRepresentation) error
	GetRealmLevelRoleMappings(accessToken string, realmName, userID string) ([]kc.RoleRepresentation, error)
	ResetPassword(accessToken string, realmName string, userID string, cred kc.CredentialRepresentation) error
	SendVerifyEmail(accessToken string, realmName string, userID string, paramKV ...string) error
	ExecuteActionsEmail(accessToken string, realmName string, userID string, actions []string, paramKV ...string) error
	SendNewEnrolmentCode(accessToken string, realmName string, userID string) (kc.SmsCodeRepresentation, error)
	SendReminderEmail(accessToken string, realmName string, userID string, paramKV ...string) error
	GetRoles(accessToken string, realmName string) ([]kc.RoleRepresentation, error)
	GetRole(accessToken string, realmName string, roleID string) (kc.RoleRepresentation, error)
	GetGroups(accessToken string, realmName string) ([]kc.GroupRepresentation, error)
	GetClientRoles(accessToken string, realmName, idClient string) ([]kc.RoleRepresentation, error)
	CreateClientRole(accessToken string, realmName, clientID string, role kc.RoleRepresentation) (string, error)
	GetGroup(accessToken string, realmName, groupID string) (kc.GroupRepresentation, error)
	GetCredentials(accessToken string, realmName string, userID string) ([]kc.CredentialRepresentation, error)
	UpdateLabelCredential(accessToken string, realmName string, userID string, credentialID string, label string) error
	DeleteCredential(accessToken string, realmName string, userID string, credentialID string) error
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	StoreOrUpdate(context.Context, string, dto.RealmConfiguration) error
	GetConfiguration(context.Context, string) (dto.RealmConfiguration, error)
}

// Component is the management component interface.
type Component interface {
	GetRealms(ctx context.Context) ([]api.RealmRepresentation, error)
	GetRealm(ctx context.Context, realmName string) (api.RealmRepresentation, error)
	GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error)
	GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error)
	DeleteUser(ctx context.Context, realmName, userID string) error
	GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error
	GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error)
	CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error)
	GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error)
	GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error)
	GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error)
	GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error)
	AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error
	ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error)
	SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error
	ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []api.RequiredAction, paramKV ...string) error
	SendNewEnrolmentCode(ctx context.Context, realmName string, userID string) (string, error)
	SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error
	GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error)
	DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error)
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
	GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error)
	UpdateRealmCustomConfiguration(ctx context.Context, realmID string, customConfig api.RealmCustomConfiguration) error
}

// Component is the management component.
type component struct {
	keycloakClient KeycloakClient
	eventDBModule  database.EventsDBModule
	configDBModule ConfigurationDBModule
	logger         internal.Logger
}

// NewComponent returns the management component.
func NewComponent(keycloakClient KeycloakClient, eventDBModule database.EventsDBModule, configDBModule ConfigurationDBModule, logger internal.Logger) Component {
	return &component{
		keycloakClient: keycloakClient,
		eventDBModule:  eventDBModule,
		configDBModule: configDBModule,
		logger:         logger,
	}
}

func (c *component) reportEvent(ctx context.Context, apiCall string, values ...string) error {
	return c.eventDBModule.ReportEvent(ctx, apiCall, "back-office", values...)
}

func (c *component) GetRealms(ctx context.Context) ([]api.RealmRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	realmsKc, err := c.keycloakClient.GetRealms(accessToken)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var realmsRep = []api.RealmRepresentation{}
	for _, realmKc := range realmsKc {
		var realmRep api.RealmRepresentation
		realmRep.ID = realmKc.Id
		realmRep.KeycloakVersion = realmKc.KeycloakVersion
		realmRep.Realm = realmKc.Realm
		realmRep.DisplayName = realmKc.DisplayName
		realmRep.Enabled = realmKc.Enabled
		realmsRep = append(realmsRep, realmRep)
	}

	return realmsRep, err

}

func (c *component) GetRealm(ctx context.Context, realm string) (api.RealmRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var realmRep api.RealmRepresentation
	realmKc, err := c.keycloakClient.GetRealm(accessToken, realm)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return api.RealmRepresentation{}, err
	}

	realmRep.ID = realmKc.Id
	realmRep.KeycloakVersion = realmKc.KeycloakVersion
	realmRep.Realm = realmKc.Realm
	realmRep.DisplayName = realmKc.DisplayName
	realmRep.Enabled = realmKc.Enabled

	return realmRep, nil
}

func (c *component) GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var clientRep api.ClientRepresentation
	clientKc, err := c.keycloakClient.GetClient(accessToken, realmName, idClient)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return api.ClientRepresentation{}, err
	}

	clientRep.ID = clientKc.Id
	clientRep.Name = clientKc.Name
	clientRep.BaseURL = clientKc.BaseUrl
	clientRep.ClientID = clientKc.ClientId
	clientRep.Protocol = clientKc.Protocol
	clientRep.Enabled = clientKc.Enabled

	return clientRep, nil
}

func (c *component) GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	clientsKc, err := c.keycloakClient.GetClients(accessToken, realmName)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var clientsRep = []api.ClientRepresentation{}
	for _, clientKc := range clientsKc {
		var clientRep api.ClientRepresentation
		clientRep.ID = clientKc.Id
		clientRep.Name = clientKc.Name
		clientRep.BaseURL = clientKc.BaseUrl
		clientRep.ClientID = clientKc.ClientId
		clientRep.Protocol = clientKc.Protocol
		clientRep.Enabled = clientKc.Enabled
		clientsRep = append(clientsRep, clientRep)
	}

	return clientsRep, nil
}

func (c *component) CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	var userRep kc.UserRepresentation

	userRep = api.ConvertToKCUser(user)

	locationURL, err := c.keycloakClient.CreateUser(accessToken, ctxRealm, realmName, userRep)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return "", err
	}

	var username = ""
	if user.Username != nil {
		username = *user.Username
	}

	//retrieve the user ID
	reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
	userID := string(reg.Find([]byte(locationURL)))

	//store the API call into the DB
	err = c.reportEvent(ctx, "API_ACCOUNT_CREATION", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username)
	if err != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "API_ACCOUNT_CREATION", database.CtEventRealmName: realmName, database.CtEventUserID: userID, database.CtEventUsername: username}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", err.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", err.Error())
		}
	}

	return locationURL, nil
}

func (c *component) DeleteUser(ctx context.Context, realmName, userID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.DeleteUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB
	err = c.reportEvent(ctx, "API_ACCOUNT_DELETION", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
	if err != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "API_ACCOUNT_DELETION", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", err.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", err.Error())
		}
	}

	return nil
}

func (c *component) GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var userRep api.UserRepresentation
	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return userRep, err
	}

	userRep = api.ConvertToAPIUser(userKc)

	var username = ""
	if userKc.Username != nil {
		username = *userKc.Username
	}

	//store the API call into the DB
	err = c.reportEvent(ctx, "GET_DETAILS", database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username)
	if err != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "GET_DETAILS", database.CtEventRealmName: realmName, database.CtEventUserID: userID, database.CtEventUsername: username}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", err.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", err.Error())
		}
	}
	return userRep, nil

}

func (c *component) UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var userRep kc.UserRepresentation

	// get the "old" user representation
	oldUserKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	// when the email changes, set the EmailVerified to false
	if user.Email != nil && oldUserKc.Email != nil && *oldUserKc.Email != *user.Email {
		var verified = false
		user.EmailVerified = &verified
	}

	// when the phone number changes, set the PhoneNumberVerified to false
	if user.PhoneNumber != nil {
		if oldUserKc.Attributes != nil {
			var m = *oldUserKc.Attributes
			if _, ok := m["phoneNumber"]; !ok || m["phoneNumber"][0] != *user.PhoneNumber {
				var verified = false
				user.PhoneNumberVerified = &verified
			}
		} else { // the user has no attributes until now, i.e. he has not set yet his phone number
			var verified = false
			user.PhoneNumberVerified = &verified
		}
	}

	userRep = api.ConvertToKCUser(user)

	// Merge the attributes coming from the old user representation and the updated user representation in order not to lose anything
	var mergedAttributes = make(map[string][]string)

	//Populate with the old attributes
	if oldUserKc.Attributes != nil {
		for key, attribute := range *oldUserKc.Attributes {
			mergedAttributes[key] = attribute
		}
	}
	// Update with the new ones
	if userRep.Attributes != nil {
		for key, attribute := range *userRep.Attributes {
			mergedAttributes[key] = attribute
		}
	}
	userRep.Attributes = &mergedAttributes

	err = c.keycloakClient.UpdateUser(accessToken, realmName, userID, userRep)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	//store the API call into the DB in case where user.Enable is present
	if user.Enabled != nil {
		var username = ""
		if user.Username != nil {
			username = *user.Username
		}

		//add ct_event_type
		var ctEventType string
		if *user.Enabled {
			// UNLOCK_ACCOUNT ct_event_type
			ctEventType = "UNLOCK_ACCOUNT"
		} else {
			// LOCK_ACCOUNT ct_event_type
			ctEventType = "LOCK_ACCOUNT"
		}

		err = c.reportEvent(ctx, ctEventType, database.CtEventRealmName, realmName, database.CtEventUserID, userID, database.CtEventUsername, username)
		if err != nil {
			//store in the logs also the event that failed to be stored in the DB
			m := map[string]interface{}{"event_name": ctEventType, database.CtEventRealmName: realmName, database.CtEventUserID: userID, database.CtEventUsername: username}
			eventJSON, errMarshal := json.Marshal(m)
			if errMarshal == nil {
				c.logger.Error("err", err.Error(), "event", string(eventJSON))
			} else {
				c.logger.Error("err", err.Error())
			}
		}
	}

	return nil
}

func (c *component) GetUsers(ctx context.Context, realmName string, groupIDs []string, paramKV ...string) (api.UsersPageRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var ctxRealm = ctx.Value(cs.CtContextRealm).(string)

	for _, groupID := range groupIDs {
		paramKV = append(paramKV, "groupId", groupID)
	}

	usersKc, err := c.keycloakClient.GetUsers(accessToken, ctxRealm, realmName, paramKV...)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return api.UsersPageRepresentation{}, err
	}

	return api.ConvertToAPIUsersPage(usersKc), nil
}

// GetUserAccountStatus gets the user status : user should be enabled in Keycloak and have multifactor activated
func (c *component) GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var res map[string]bool

	res = make(map[string]bool)
	res["enabled"] = false

	userKc, err := c.keycloakClient.GetUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return res, err
	}

	if !*userKc.Enabled {
		return res, nil
	}

	creds, err := c.GetCredentialsForUser(ctx, realmName, userID)
	res["enabled"] = len(creds) > 1
	return res, err
}

func (c *component) GetRolesOfUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetRealmLevelRoleMappings(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]api.GroupRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	groupsKc, err := c.keycloakClient.GetGroupsOfUser(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var groupsRep = []api.GroupRepresentation{}
	for _, groupKc := range groupsKc {
		var groupRep api.GroupRepresentation
		groupRep.ID = groupKc.Id
		groupRep.Name = groupKc.Name

		groupsRep = append(groupsRep, groupRep)
	}

	return groupsRep, nil
}

func (c *component) GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetClientRoleMappings(accessToken, realmName, userID, clientID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var rolesRep = []kc.RoleRepresentation{}
	for _, role := range roles {
		var roleRep kc.RoleRepresentation
		roleRep.Id = role.ID
		roleRep.Name = role.Name
		roleRep.Composite = role.Composite
		roleRep.ClientRole = role.ClientRole
		roleRep.ContainerId = role.ContainerID
		roleRep.Description = role.Description

		rolesRep = append(rolesRep, roleRep)
	}

	err := c.keycloakClient.AddClientRolesToUserRoleMapping(accessToken, realmName, userID, clientID, rolesRep)

	if err != nil {
		c.logger.Warn("err", err.Error())
	}

	return err
}

func (c *component) ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var pwd string
	var err error
	var credKc kc.CredentialRepresentation
	var passwordType = "password"
	credKc.Type = &passwordType

	if password.Value == nil {
		// the commented code respects the following scenario: if the realm has a pwd policy, the generated pwd respects this policy
		/*
			// no password value was provided; a new password, that respects the password policy of the realm, will be generated
			var minLength int = 8

			//obtain password policy
			realmKc, err := c.keycloakClient.GetRealm(accessToken, realmName)
			if err == nil {
				// generate password according to the policy of the realm
				pwd, err = internal.GeneratePassword(realmKc.PasswordPolicy, minLength, userID)
				if err != nil {
					return pwd, err
				}
				credKc.Value = &pwd
			} else {
				return "", err
			}
		*/
		// generate a password of the format UpperCase + 6 digits + LowerCase
		var nbUpperCase = 1
		var nbDigits = 6
		var nbLowerCase = 1
		pwd = internal.GenerateInitialCode(nbUpperCase, nbDigits, nbLowerCase)
		credKc.Value = &pwd
	} else {
		credKc.Value = password.Value
	}

	err = c.keycloakClient.ResetPassword(accessToken, realmName, userID, credKc)
	if err != nil {
		c.logger.Warn("err", err.Error())
		return pwd, err
	}

	//store the API call into the DB
	err = c.reportEvent(ctx, "INIT_PASSWORD", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
	if err != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "INIT_PASSWORD", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", err.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", err.Error())
		}
	}

	return pwd, nil
}

func (c *component) SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.SendVerifyEmail(accessToken, realmName, userID, paramKV...)

	if err != nil {
		c.logger.Warn("err", err.Error())
	}

	return err
}

func (c *component) ExecuteActionsEmail(ctx context.Context, realmName string, userID string, requiredActions []api.RequiredAction, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var actions = []string{}

	for _, requiredAction := range requiredActions {
		actions = append(actions, string(requiredAction))
		if string(requiredAction) == initPasswordAction {
			//store the API call into the DB
			err := c.reportEvent(ctx, "INIT_PASSWORD", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
			if err != nil {
				//store in the logs also the event that failed to be stored in the DB
				m := map[string]interface{}{"event_name": "INIT_PASSWORD", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
				eventJSON, errMarshal := json.Marshal(m)
				if errMarshal == nil {
					c.logger.Error("err", err.Error(), "event", string(eventJSON))
				} else {
					c.logger.Error("err", err.Error())
				}

			}
		}
	}

	err := c.keycloakClient.ExecuteActionsEmail(accessToken, realmName, userID, actions, paramKV...)

	if err != nil {
		c.logger.Warn("err", err.Error())
	}

	return err
}

func (c *component) SendNewEnrolmentCode(ctx context.Context, realmName string, userID string) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	smsCodeKc, err := c.keycloakClient.SendNewEnrolmentCode(accessToken, realmName, userID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return "", err
	}

	// store the API call into the DB
	errEvent := c.reportEvent(ctx, "SMS_CHALLENGE", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
	if errEvent != nil {
		//store in the logs also the event that failed to be stored in the DB
		m := map[string]interface{}{"event_name": "SMS_CHALLENGE", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
		eventJSON, errMarshal := json.Marshal(m)
		if errMarshal == nil {
			c.logger.Error("err", errEvent.Error(), "event", string(eventJSON))
		} else {
			c.logger.Error("err", errEvent.Error())
		}
	}

	return *smsCodeKc.Code, err
}

func (c *component) SendReminderEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	err := c.keycloakClient.SendReminderEmail(accessToken, realmName, userID, paramKV...)

	if err != nil {
		c.logger.Warn("err", err.Error())
	}

	return err
}

func (c *component) GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	credsKc, err := c.keycloakClient.GetCredentials(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var credsRep = []api.CredentialRepresentation{}
	for _, credKc := range credsKc {
		credsRep = append(credsRep, api.ConvertCredential(&credKc))
	}

	return credsRep, err
}

func (c *component) DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the list of credentails of the user
	credsKc, err := c.keycloakClient.GetCredentials(accessToken, realmName, userID)
	if err != nil {
		c.logger.Warn("msg", "Could not obtain list of credentials", "err", err.Error())
	}

	err = c.keycloakClient.DeleteCredential(accessToken, realmName, userID, credentialID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return err
	}

	// if a credential other than the password was deleted, record the event 2ND_FACTOR_REMOVED in the audit DB
	for _, credKc := range credsKc {
		if *credKc.Id == credentialID && *credKc.Type != "password" {

			errEvent := c.reportEvent(ctx, "2ND_FACTOR_REMOVED", database.CtEventRealmName, realmName, database.CtEventUserID, userID)
			if errEvent != nil {
				//store in the logs also the event that failed to be stored in the DB
				m := map[string]interface{}{"event_name": "2ND_FACTOR_REMOVED", database.CtEventRealmName: realmName, database.CtEventUserID: userID}
				eventJSON, errMarshal := json.Marshal(m)
				if errMarshal == nil {
					c.logger.Error("err", errEvent.Error(), "event", string(eventJSON))
				} else {
					c.logger.Error("err", errEvent.Error())
				}
			}
			break
		}
	}

	return err
}

func (c *component) GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetRoles(accessToken, realmName)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var roleRep api.RoleRepresentation
	roleKc, err := c.keycloakClient.GetRole(accessToken, realmName, roleID)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return api.RoleRepresentation{}, err
	}

	roleRep.ID = roleKc.Id
	roleRep.Name = roleKc.Name
	roleRep.Composite = roleKc.Composite
	roleRep.ClientRole = roleKc.ClientRole
	roleRep.ContainerID = roleKc.ContainerId
	roleRep.Description = roleKc.Description

	return roleRep, nil
}

func (c *component) GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	groupsKc, err := c.keycloakClient.GetGroups(accessToken, realmName)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var groupsRep = []api.GroupRepresentation{}
	for _, groupKc := range groupsKc {
		var groupRep api.GroupRepresentation
		groupRep.ID = groupKc.Id
		groupRep.Name = groupKc.Name

		groupsRep = append(groupsRep, groupRep)
	}

	return groupsRep, nil
}

func (c *component) GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	rolesKc, err := c.keycloakClient.GetClientRoles(accessToken, realmName, idClient)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return nil, err
	}

	var rolesRep = []api.RoleRepresentation{}
	for _, roleKc := range rolesKc {
		var roleRep api.RoleRepresentation
		roleRep.ID = roleKc.Id
		roleRep.Name = roleKc.Name
		roleRep.Composite = roleKc.Composite
		roleRep.ClientRole = roleKc.ClientRole
		roleRep.ContainerID = roleKc.ContainerId
		roleRep.Description = roleKc.Description

		rolesRep = append(rolesRep, roleRep)
	}

	return rolesRep, nil
}

func (c *component) CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	var roleRep kc.RoleRepresentation
	roleRep.Id = role.ID
	roleRep.Name = role.Name
	roleRep.Composite = role.Composite
	roleRep.ClientRole = role.ClientRole
	roleRep.ContainerId = role.ContainerID
	roleRep.Description = role.Description

	locationURL, err := c.keycloakClient.CreateClientRole(accessToken, realmName, clientID, roleRep)

	if err != nil {
		c.logger.Warn("err", err.Error())
		return "", err
	}

	return locationURL, nil
}

// Retrieve the configuration from the database
func (c *component) GetRealmCustomConfiguration(ctx context.Context, realmName string) (api.RealmCustomConfiguration, error) {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)
	var falseBool = false

	// get the realm config from Keycloak
	realmConfig, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Warn("err", err.Error())
		return api.RealmCustomConfiguration{}, err
	}
	// from the realm ID, fetch the custom configuration
	realmID := realmConfig.Id
	config, err := c.configDBModule.GetConfiguration(ctx, *realmID)
	// DB error
	if err != nil {
		switch e := errors.Cause(err).(type) {
		case internal.MissingRealmConfigurationErr:
			c.logger.Warn("message", e.Error())
			return api.RealmCustomConfiguration{
				DefaultClientID:                     new(string),
				DefaultRedirectURI:                  new(string),
				APISelfAuthenticatorDeletionEnabled: &falseBool,
				APISelfPasswordChangeEnabled:        &falseBool,
				APISelfMailEditingEnabled:           &falseBool,
				APISelfAccountDeletionEnabled:       &falseBool,
				ShowAuthenticatorsTab:               &falseBool,
				ShowPasswordTab:                     &falseBool,
				ShowMailEditing:                     &falseBool,
				ShowAccountDeletionButton:           &falseBool,
			}, nil
		default:
			c.logger.Error("err", e.Error())
			return api.RealmCustomConfiguration{}, err
		}
	}

	return api.RealmCustomConfiguration{
		DefaultClientID:                     config.DefaultClientID,
		DefaultRedirectURI:                  config.DefaultRedirectURI,
		APISelfAuthenticatorDeletionEnabled: config.APISelfAuthenticatorDeletionEnabled,
		APISelfPasswordChangeEnabled:        config.APISelfPasswordChangeEnabled,
		APISelfMailEditingEnabled:           config.APISelfMailEditingEnabled,
		APISelfAccountDeletionEnabled:       config.APISelfAccountDeletionEnabled,
		ShowAuthenticatorsTab:               config.ShowAuthenticatorsTab,
		ShowPasswordTab:                     config.ShowPasswordTab,
		ShowMailEditing:                     config.ShowMailEditing,
		ShowAccountDeletionButton:           config.ShowAccountDeletionButton,
	}, nil
}

// Update the configuration in the database; verify that the content of the configuration is coherent with Keycloak configuration
func (c *component) UpdateRealmCustomConfiguration(ctx context.Context, realmName string, customConfig api.RealmCustomConfiguration) error {
	var accessToken = ctx.Value(cs.CtContextAccessToken).(string)

	// get the realm config from Keycloak
	realmConfig, err := c.keycloakClient.GetRealm(accessToken, realmName)
	if err != nil {
		c.logger.Error("err", err.Error())
		return err
	}
	// get the desired client (from its ID)
	clients, err := c.keycloakClient.GetClients(accessToken, realmName)
	if err != nil {
		c.logger.Error("err", err.Error())
		return err
	}

	// Both DefaultClientID and DefaultRedirectURI must be specified together or not at all
	if (customConfig.DefaultClientID == nil && customConfig.DefaultRedirectURI != nil) ||
		(customConfig.DefaultClientID != nil && customConfig.DefaultRedirectURI == nil) {
		return errorhandler.Error{
			Status:  400,
			Message: internal.MsgErrInvalidParam + "." + internal.ClientID + "And" + internal.RedirectURI,
		}
	}

	if customConfig.DefaultClientID != nil && customConfig.DefaultRedirectURI != nil {
		var match = false

		for _, client := range clients {
			if *client.ClientId != *customConfig.DefaultClientID {
				continue
			}
			for _, redirectURI := range *client.RedirectUris {
				// escape the regex-specific characters (dots for intance)...
				matcher := regexp.QuoteMeta(redirectURI)
				// ... but keep the stars
				matcher = strings.Replace(matcher, "\\*", "*", -1)
				match, _ = regexp.MatchString(matcher, *customConfig.DefaultRedirectURI)
				if match {
					break
				}
			}
		}

		if !match {
			return errorhandler.Error{
				Status:  400,
				Message: internal.MsgErrInvalidParam + "." + internal.ClientID + "Or" + internal.RedirectURI,
			}
		}
	}

	// transform customConfig object into DTO
	var config = dto.RealmConfiguration{
		DefaultClientID:                     customConfig.DefaultClientID,
		DefaultRedirectURI:                  customConfig.DefaultRedirectURI,
		APISelfAuthenticatorDeletionEnabled: customConfig.APISelfAuthenticatorDeletionEnabled,
		APISelfPasswordChangeEnabled:        customConfig.APISelfPasswordChangeEnabled,
		APISelfMailEditingEnabled:           customConfig.APISelfMailEditingEnabled,
		APISelfAccountDeletionEnabled:       customConfig.APISelfAccountDeletionEnabled,
		ShowAuthenticatorsTab:               customConfig.ShowAuthenticatorsTab,
		ShowPasswordTab:                     customConfig.ShowPasswordTab,
		ShowMailEditing:                     customConfig.ShowMailEditing,
		ShowAccountDeletionButton:           customConfig.ShowAccountDeletionButton,
	}

	// from the realm ID, update the custom configuration in the DB
	realmID := realmConfig.Id
	err = c.configDBModule.StoreOrUpdate(ctx, *realmID, config)
	return err
}
