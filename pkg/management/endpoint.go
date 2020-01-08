package management

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetRealms                      endpoint.Endpoint
	GetRealm                       endpoint.Endpoint
	GetClient                      endpoint.Endpoint
	GetClients                     endpoint.Endpoint
	GetRequiredActions             endpoint.Endpoint
	DeleteUser                     endpoint.Endpoint
	GetUser                        endpoint.Endpoint
	UpdateUser                     endpoint.Endpoint
	GetUsers                       endpoint.Endpoint
	CreateUser                     endpoint.Endpoint
	GetRolesOfUser                 endpoint.Endpoint
	GetGroupsOfUser                endpoint.Endpoint
	GetUserAccountStatus           endpoint.Endpoint
	GetClientRoleForUser           endpoint.Endpoint
	AddClientRoleToUser            endpoint.Endpoint
	ResetPassword                  endpoint.Endpoint
	SendVerifyEmail                endpoint.Endpoint
	ExecuteActionsEmail            endpoint.Endpoint
	SendNewEnrolmentCode           endpoint.Endpoint
	SendReminderEmail              endpoint.Endpoint
	ResetSmsCounter                endpoint.Endpoint
	CreateRecoveryCode             endpoint.Endpoint
	GetCredentialsForUser          endpoint.Endpoint
	DeleteCredentialsForUser       endpoint.Endpoint
	GetRoles                       endpoint.Endpoint
	GetRole                        endpoint.Endpoint
	GetGroups                      endpoint.Endpoint
	GetClientRoles                 endpoint.Endpoint
	CreateClientRole               endpoint.Endpoint
	GetRealmCustomConfiguration    endpoint.Endpoint
	UpdateRealmCustomConfiguration endpoint.Endpoint
}

// ManagementComponent is the interface of the component to send a query to Keycloak.
type ManagementComponent interface {
	GetRealms(ctx context.Context) ([]api.RealmRepresentation, error)
	GetRealm(ctx context.Context, realmName string) (api.RealmRepresentation, error)
	GetClient(ctx context.Context, realmName, idClient string) (api.ClientRepresentation, error)
	GetClients(ctx context.Context, realmName string) ([]api.ClientRepresentation, error)
	GetRequiredActions(ctx context.Context, realmName string) ([]api.RequiredActionRepresentation, error)
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
	ResetSmsCounter(ctx context.Context, realmName string, userID string) error
	CreateRecoveryCode(ctx context.Context, realmName string, userID string) (string, error)
	GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error)
	DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	GetGroups(ctx context.Context, realmName string) ([]api.GroupRepresentation, error)
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
	GetRealmCustomConfiguration(ctx context.Context, realmID string) (api.RealmCustomConfiguration, error)
	UpdateRealmCustomConfiguration(ctx context.Context, realmID string, customConfig api.RealmCustomConfiguration) error
}

// MakeGetRealmsEndpoint makes the Realms endpoint to retrieve all available realms.
func MakeGetRealmsEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return managementComponent.GetRealms(ctx)
	}
}

// MakeGetRealmEndpoint makes the Realm endpoint to retrieve a realm.
func MakeGetRealmEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRealm(ctx, m["realm"])
	}
}

// MakeGetClientEndpoint creates an endpoint for GetClient
func MakeGetClientEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClient(ctx, m["realm"], m["clientID"])
	}
}

// MakeGetClientsEndpoint creates an endpoint for GetClients
func MakeGetClientsEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClients(ctx, m["realm"])
	}
}

// MakeGetRequiredActionsEndpoint creates an endpoint for GetRequiredActions
func MakeGetRequiredActionsEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRequiredActions(ctx, m["realm"])
	}
}

// MakeCreateUserEndpoint makes the endpoint to create a user.
func MakeCreateUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		if user.Groups == nil || len(*user.Groups) == 0 {
			return nil, errorhandler.CreateMissingParameterError(internal.Groups)
		}

		var keycloakLocation string
		keycloakLocation, err = managementComponent.CreateUser(ctx, m["realm"], user)

		if err != nil {
			return nil, err
		}

		url, err := convertLocationURL(keycloakLocation, m["scheme"], m["host"])
		// TODO: log the error and the unhappy url

		return LocationHeader{
			URL: url,
		}, nil
	}
}

// MakeDeleteUserEndpoint creates an endpoint for DeleteUser
func MakeDeleteUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, managementComponent.DeleteUser(ctx, m["realm"], m["userID"])
	}
}

// MakeGetUserEndpoint creates an endpoint for GetUser
func MakeGetUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetUser(ctx, m["realm"], m["userID"])
	}
}

// MakeUpdateUserEndpoint creates an endpoint for UpdateUser
func MakeUpdateUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + internal.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		return nil, managementComponent.UpdateUser(ctx, m["realm"], m["userID"], user)
	}
}

// MakeGetUsersEndpoint creates an endpoint for GetUsers
func MakeGetUsersEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"email", "firstName", "lastName", "username", "search", "first", "max"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		_, ok := m["groupIds"]
		if !ok {
			return nil, errorhandler.CreateMissingParameterError(internal.GroudIDs)
		}

		groupIDs := strings.Split(m["groupIds"], ",")

		return managementComponent.GetUsers(ctx, m["realm"], groupIDs, paramKV...)
	}
}

// MakeGetRolesOfUserEndpoint creates an endpoint for GetRolesOfUser
func MakeGetRolesOfUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRolesOfUser(ctx, m["realm"], m["userID"])
	}
}

// MakeGetGroupsOfUserEndpoint creates an endpoint for GetGroupsOfUser
func MakeGetGroupsOfUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetGroupsOfUser(ctx, m["realm"], m["userID"])
	}
}

// MakeGetUserAccountStatusEndpoint creates an endpoint for GetUserAccountStatus
func MakeGetUserAccountStatusEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetUserAccountStatus(ctx, m["realm"], m["userID"])
	}
}

// MakeGetClientRolesForUserEndpoint creates an endpoint for GetClientRolesForUser
func MakeGetClientRolesForUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClientRolesForUser(ctx, m["realm"], m["userID"], m["clientID"])
	}
}

// MakeAddClientRolesToUserEndpoint creates an endpoint for AddClientRolesToUser
func MakeAddClientRolesToUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var roles []api.RoleRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &roles); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		for _, role := range roles {
			if err = role.Validate(); err != nil {
				return nil, errorhandler.CreateBadRequestError(err.Error())
			}
		}

		return nil, managementComponent.AddClientRolesToUser(ctx, m["realm"], m["userID"], m["clientID"], roles)
	}
}

// MakeResetPasswordEndpoint creates an endpoint for ResetPassword
func MakeResetPasswordEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var password api.PasswordRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &password); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = password.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		pwd, err := managementComponent.ResetPassword(ctx, m["realm"], m["userID"], password)
		if pwd != "" {
			return pwd, err
		}
		return nil, err
	}
}

// MakeSendVerifyEmailEndpoint creates an endpoint for SendVerifyEmail
func MakeSendVerifyEmailEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"client_id", "redirect_uri"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		return nil, managementComponent.SendVerifyEmail(ctx, m["realm"], m["userID"], paramKV...)
	}
}

// MakeExecuteActionsEmailEndpoint creates an endpoint for ExecuteActionsEmail
func MakeExecuteActionsEmailEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var paramKV []string
		for _, key := range []string{"client_id", "redirect_uri", "lifespan"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		//extract the actions
		var actions []api.RequiredAction

		if err = json.Unmarshal([]byte(m["body"]), &actions); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		for _, action := range actions {
			if err = action.Validate(); err != nil {
				return nil, errorhandler.CreateBadRequestError(err.Error())
			}
		}

		return nil, managementComponent.ExecuteActionsEmail(ctx, m["realm"], m["userID"], actions, paramKV...)
	}
}

// MakeSendNewEnrolmentCodeEndpoint creates an endpoint for SendNewEnrolmentCode
func MakeSendNewEnrolmentCodeEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		code, err := managementComponent.SendNewEnrolmentCode(ctx, m["realm"], m["userID"])
		return map[string]string{"code": code}, err
	}
}

// MakeSendReminderEmailEndpoint creates an endpoint for SendReminderEmail
func MakeSendReminderEmailEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"client_id", "redirect_uri", "lifespan"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		return nil, managementComponent.SendReminderEmail(ctx, m["realm"], m["userID"], paramKV...)
	}
}

// MakeResetSmsCounterEndpoint creates an endpoint for ResetSmsCounter
func MakeResetSmsCounterEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, managementComponent.ResetSmsCounter(ctx, m["realm"], m["userID"])
	}
}

// MakeCreateRecoveryCodeEndpoint creates an endpoint for MakeCreateRecoveryCode
func MakeCreateRecoveryCodeEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.CreateRecoveryCode(ctx, m["realm"], m["userID"])
	}
}

// MakeGetCredentialsForUserEndpoint creates an endpoint for GetCredentialsForUser
func MakeGetCredentialsForUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetCredentialsForUser(ctx, m["realm"], m["userID"])
	}
}

// MakeDeleteCredentialsForUserEndpoint creates an endpoint for DeleteCredentialsForUser
func MakeDeleteCredentialsForUserEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, managementComponent.DeleteCredentialsForUser(ctx, m["realm"], m["userID"], m["credentialID"])
	}
}

// MakeGetRolesEndpoint creates an endpoint for GetRoles
func MakeGetRolesEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRoles(ctx, m["realm"])
	}
}

// MakeGetRoleEndpoint creates an endpoint for GetRole
func MakeGetRoleEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRole(ctx, m["realm"], m["roleID"])
	}
}

// MakeGetGroupsEndpoint creates an endpoint for GetGroups
func MakeGetGroupsEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetGroups(ctx, m["realm"])
	}
}

// MakeGetClientRolesEndpoint creates an endpoint for GetClientRoles
func MakeGetClientRolesEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClientRoles(ctx, m["realm"], m["clientID"])
	}
}

// MakeCreateClientRoleEndpoint creates an endpoint for CreateClientRole
func MakeCreateClientRoleEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var role api.RoleRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &role); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = role.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		var keycloakLocation string
		keycloakLocation, err = managementComponent.CreateClientRole(ctx, m["realm"], m["clientID"], role)

		if err != nil {
			return nil, err
		}

		url, err := convertLocationURL(keycloakLocation, m["scheme"], m["host"])
		// TODO: log the error and the unhappy url

		return LocationHeader{
			URL: url,
		}, nil
	}
}

// MakeGetRealmCustomConfigurationEndpoint creates an endpoint for GetRealmCustomConfiguration
func MakeGetRealmCustomConfigurationEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRealmCustomConfiguration(ctx, m["realm"])
	}
}

// MakeUpdateRealmCustomConfigurationEndpoint creates an endpoint for UpdateRealmCustomConfiguration
func MakeUpdateRealmCustomConfigurationEndpoint(managementComponent ManagementComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		configJSON := []byte(m["body"])

		var customConfig api.RealmCustomConfiguration

		if err = json.Unmarshal(configJSON, &customConfig); err != nil {
			return nil, errorhandler.CreateBadRequestError(internal.MsgErrInvalidParam + "." + internal.Body)
		}

		if err = customConfig.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		return nil, managementComponent.UpdateRealmCustomConfiguration(ctx, m["realm"], customConfig)
	}
}

// LocationHeader type
type LocationHeader struct {
	URL string
}

// ConvertLocationError type
type ConvertLocationError struct {
	Location string
}

func (e ConvertLocationError) Error() string {
	return fmt.Sprintf("locationReceivedFromKeycloakDoesNotMatchRegexp.%s", e.Location)
}

// We are currently using a mapping 1:1 for REST API of Bridge and Keycloak, thus we take a shortcut to convert the location of the resource
func convertLocationURL(originalURL string, scheme string, host string) (string, error) {
	delimiter := regexp.MustCompile(`(\/auth\/admin)|(auth\/realms\/[a-zA-Z0-9_-]+\/api\/admin)`)
	var splitURL = delimiter.Split(originalURL, 2)

	if len(splitURL) != 2 {
		return "InvalidLocation", ConvertLocationError{
			Location: originalURL,
		}
	}

	return scheme + "://" + host + "/management" + splitURL[1], nil
}
