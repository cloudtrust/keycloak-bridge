package management

import (
	"context"
	"encoding/json"
	"strings"

	api "github.com/cloudtrust/keycloak-bridge/api/management"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetRealms                      endpoint.Endpoint
	GetRealm                       endpoint.Endpoint
	GetClient                      endpoint.Endpoint
	GetClients                     endpoint.Endpoint
	DeleteUser                     endpoint.Endpoint
	GetUser                        endpoint.Endpoint
	UpdateUser                     endpoint.Endpoint
	GetUsers                       endpoint.Endpoint
	CreateUser                     endpoint.Endpoint
	GetUserAccountStatus           endpoint.Endpoint
	GetClientRoleForUser           endpoint.Endpoint
	AddClientRoleToUser            endpoint.Endpoint
	GetRealmRoleForUser            endpoint.Endpoint
	ResetPassword                  endpoint.Endpoint
	SendVerifyEmail                endpoint.Endpoint
	ExecuteActionsEmail            endpoint.Endpoint
	GetCredentialsForUser          endpoint.Endpoint
	DeleteCredentialsForUser       endpoint.Endpoint
	GetRoles                       endpoint.Endpoint
	GetRole                        endpoint.Endpoint
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
	DeleteUser(ctx context.Context, realmName, userID string) error
	GetUser(ctx context.Context, realmName, userID string) (api.UserRepresentation, error)
	UpdateUser(ctx context.Context, realmName, userID string, user api.UserRepresentation) error
	GetUsers(ctx context.Context, realmName, group string, paramKV ...string) ([]api.UserRepresentation, error)
	CreateUser(ctx context.Context, realmName string, user api.UserRepresentation) (string, error)
	GetUserAccountStatus(ctx context.Context, realmName, userID string) (map[string]bool, error)
	GetClientRolesForUser(ctx context.Context, realmName, userID, clientID string) ([]api.RoleRepresentation, error)
	AddClientRolesToUser(ctx context.Context, realmName, userID, clientID string, roles []api.RoleRepresentation) error
	GetRealmRolesForUser(ctx context.Context, realmName, userID string) ([]api.RoleRepresentation, error)
	ResetPassword(ctx context.Context, realmName string, userID string, password api.PasswordRepresentation) error
	SendVerifyEmail(ctx context.Context, realmName string, userID string, paramKV ...string) error
	ExecuteActionsEmail(ctx context.Context, realmName string, userID string, actions []string, paramKV ...string) error
	GetCredentialsForUser(ctx context.Context, realmName string, userID string) ([]api.CredentialRepresentation, error)
	DeleteCredentialsForUser(ctx context.Context, realmName string, userID string, credentialID string) error
	GetRoles(ctx context.Context, realmName string) ([]api.RoleRepresentation, error)
	GetRole(ctx context.Context, realmName string, roleID string) (api.RoleRepresentation, error)
	GetClientRoles(ctx context.Context, realmName, idClient string) ([]api.RoleRepresentation, error)
	CreateClientRole(ctx context.Context, realmName, clientID string, role api.RoleRepresentation) (string, error)
	GetRealmCustomConfiguration(ctx context.Context, realmID string) (api.RealmCustomConfiguration, error)
	UpdateRealmCustomConfiguration(ctx context.Context, realmID string, customConfig api.RealmCustomConfiguration) error
}

// MakeRealmsEndpoint makes the Realms endpoint to retrieve all available realms.
func MakeGetRealmsEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return managementComponent.GetRealms(ctx)
	}
}

// MakeRealmEndpoint makes the Realm endpoint to retrieve a realm.
func MakeGetRealmEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRealm(ctx, m["realm"])
	}
}

func MakeGetClientEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClient(ctx, m["realm"], m["clientID"])
	}
}

func MakeGetClientsEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClients(ctx, m["realm"])
	}
}

// MakeCreateUserEndpoint makes the endpoint to create a user.
func MakeCreateUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		userJson := []byte(m["body"])

		var user api.UserRepresentation
		err := json.Unmarshal(userJson, &user)

		if err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = managementComponent.CreateUser(ctx, m["realm"], user)

		if err != nil {
			return nil, err
		}

		return LocationHeader{
			URL: convertLocationUrl(keycloakLocation, m["scheme"], m["host"]),
		}, nil
	}
}

func MakeDeleteUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, managementComponent.DeleteUser(ctx, m["realm"], m["userID"])
	}
}

func MakeGetUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetUser(ctx, m["realm"], m["userID"])
	}
}

func MakeUpdateUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		userJson := []byte(m["body"])

		var user api.UserRepresentation
		err := json.Unmarshal(userJson, &user)

		if err != nil {
			return nil, err
		}

		return nil, managementComponent.UpdateUser(ctx, m["realm"], m["userID"], user)
	}
}

func MakeGetUsersEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"email", "firstName", "lastName", "max", "username", "group"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		group, ok := m["group"]
		if !ok {
			return nil, CreateMissingParameterError("group")
		}

		return managementComponent.GetUsers(ctx, m["realm"], group, paramKV...)
	}
}

func MakeGetUserAccountStatusEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetUserAccountStatus(ctx, m["realm"], m["userID"])
	}
}

func MakeGetClientRolesForUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClientRolesForUser(ctx, m["realm"], m["userID"], m["clientID"])
	}
}

func MakeAddClientRolesToUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		rolesJson := []byte(m["body"])

		var roles []api.RoleRepresentation
		err := json.Unmarshal(rolesJson, &roles)

		if err != nil {
			return nil, err
		}

		return nil, managementComponent.AddClientRolesToUser(ctx, m["realm"], m["userID"], m["clientID"], roles)
	}
}

func MakeGetRealmRolesForUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRealmRolesForUser(ctx, m["realm"], m["userID"])
	}
}

func MakeResetPasswordEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		passwordJson := []byte(m["body"])

		var password api.PasswordRepresentation
		err := json.Unmarshal(passwordJson, &password)

		if err != nil {
			return nil, err
		}

		return nil, managementComponent.ResetPassword(ctx, m["realm"], m["userID"], password)
	}
}

func MakeSendVerifyEmailEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
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

func MakeExecuteActionsEmailEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"client_id", "redirect_uri", "lifespan"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		//extract the actions
		var actions []string
		err := json.Unmarshal([]byte(m["body"]), &actions)

		if err != nil {
			return nil, err
		}

		return nil, managementComponent.ExecuteActionsEmail(ctx, m["realm"], m["userID"], actions, paramKV...)
	}
}

func MakeGetCredentialsForUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetCredentialsForUser(ctx, m["realm"], m["userID"])
	}
}

func MakeDeleteCredentialsForUserEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, managementComponent.DeleteCredentialsForUser(ctx, m["realm"], m["userID"], m["credentialID"])
	}
}

func MakeGetRolesEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRoles(ctx, m["realm"])
	}
}

func MakeGetRoleEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRole(ctx, m["realm"], m["roleID"])
	}
}

func MakeGetClientRolesEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetClientRoles(ctx, m["realm"], m["clientID"])
	}
}

func MakeCreateClientRoleEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		roleJson := []byte(m["body"])

		var role api.RoleRepresentation
		err := json.Unmarshal(roleJson, &role)

		if err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = managementComponent.CreateClientRole(ctx, m["realm"], m["clientID"], role)

		if err != nil {
			return nil, err
		}

		return LocationHeader{
			URL: convertLocationUrl(keycloakLocation, m["scheme"], m["host"]),
		}, nil
	}
}

func MakeGetRealmCustomConfigurationEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return managementComponent.GetRealmCustomConfiguration(ctx, m["realm"])
	}
}

func MakeUpdateRealmCustomConfigurationEndpoint(managementComponent ManagementComponent) endpoint.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		configJson := []byte(m["body"])

		var customConfig api.RealmCustomConfiguration
		err := json.Unmarshal(configJson, &customConfig)
		if err != nil {
			return nil, err
		}
		return nil, managementComponent.UpdateRealmCustomConfiguration(ctx, m["realm"], customConfig)
	}
}

type LocationHeader struct {
	URL string
}

// We are currently using a mapping 1:1 for REST API of Brdige and Keycloak, thus we take a shortcut to convert the location of the resource
func convertLocationUrl(originalURL string, scheme string, host string) string {
	var splitURL = strings.Split(originalURL, "/auth/admin")
	return scheme + "://" + host + "/management" + splitURL[1]
}