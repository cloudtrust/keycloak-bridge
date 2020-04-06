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
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetRealms          endpoint.Endpoint
	GetRealm           endpoint.Endpoint
	GetClient          endpoint.Endpoint
	GetClients         endpoint.Endpoint
	GetRequiredActions endpoint.Endpoint

	DeleteUser                endpoint.Endpoint
	GetUser                   endpoint.Endpoint
	UpdateUser                endpoint.Endpoint
	GetUsers                  endpoint.Endpoint
	CreateUser                endpoint.Endpoint
	GetRolesOfUser            endpoint.Endpoint
	GetGroupsOfUser           endpoint.Endpoint
	SetGroupsToUser           endpoint.Endpoint
	GetAvailableTrustIDGroups endpoint.Endpoint
	GetTrustIDGroupsOfUser    endpoint.Endpoint
	SetTrustIDGroupsToUser    endpoint.Endpoint
	GetUserAccountStatus      endpoint.Endpoint
	GetClientRoleForUser      endpoint.Endpoint
	AddClientRoleToUser       endpoint.Endpoint

	ResetPassword            endpoint.Endpoint
	ExecuteActionsEmail      endpoint.Endpoint
	SendNewEnrolmentCode     endpoint.Endpoint
	SendReminderEmail        endpoint.Endpoint
	ResetSmsCounter          endpoint.Endpoint
	CreateRecoveryCode       endpoint.Endpoint
	GetCredentialsForUser    endpoint.Endpoint
	DeleteCredentialsForUser endpoint.Endpoint
	ClearUserLoginFailures   endpoint.Endpoint
	GetAttackDetectionStatus endpoint.Endpoint

	GetRoles         endpoint.Endpoint
	GetRole          endpoint.Endpoint
	GetClientRoles   endpoint.Endpoint
	CreateClientRole endpoint.Endpoint

	GetGroups            endpoint.Endpoint
	CreateGroup          endpoint.Endpoint
	DeleteGroup          endpoint.Endpoint
	GetAuthorizations    endpoint.Endpoint
	UpdateAuthorizations endpoint.Endpoint
	GetActions           endpoint.Endpoint

	GetRealmCustomConfiguration         endpoint.Endpoint
	UpdateRealmCustomConfiguration      endpoint.Endpoint
	GetRealmAdminConfiguration          endpoint.Endpoint
	UpdateRealmAdminConfiguration       endpoint.Endpoint
	GetRealmBackOfficeConfiguration     endpoint.Endpoint
	UpdateRealmBackOfficeConfiguration  endpoint.Endpoint
	GetUserRealmBackOfficeConfiguration endpoint.Endpoint

	LinkShadowUser endpoint.Endpoint
}

// MakeGetRealmsEndpoint makes the Realms endpoint to retrieve all available realms.
func MakeGetRealmsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetRealms(ctx)
	}
}

// MakeGetRealmEndpoint makes the Realm endpoint to retrieve a realm.
func MakeGetRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRealm(ctx, m["realm"])
	}
}

// MakeGetClientEndpoint creates an endpoint for GetClient
func MakeGetClientEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClient(ctx, m["realm"], m["clientID"])
	}
}

// MakeGetClientsEndpoint creates an endpoint for GetClients
func MakeGetClientsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClients(ctx, m["realm"])
	}
}

// MakeGetRequiredActionsEndpoint creates an endpoint for GetRequiredActions
func MakeGetRequiredActionsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRequiredActions(ctx, m["realm"])
	}
}

// MakeCreateUserEndpoint makes the endpoint to create a user.
func MakeCreateUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, err
		}

		if user.Groups == nil || len(*user.Groups) == 0 {
			return nil, errorhandler.CreateMissingParameterError(msg.Groups)
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateUser(ctx, m["realm"], user)

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
func MakeDeleteUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteUser(ctx, m["realm"], m["userID"])
	}
}

// MakeGetUserEndpoint creates an endpoint for GetUser
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUser(ctx, m["realm"], m["userID"])
	}
}

// MakeUpdateUserEndpoint creates an endpoint for UpdateUser
func MakeUpdateUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + msg.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateUser(ctx, m["realm"], m["userID"], user)
	}
}

// MakeGetUsersEndpoint creates an endpoint for GetUsers
func MakeGetUsersEndpoint(component Component) cs.Endpoint {
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
			return nil, errorhandler.CreateMissingParameterError(msg.GroupIDs)
		}

		groupIDs := strings.Split(m["groupIds"], ",")

		return component.GetUsers(ctx, m["realm"], groupIDs, paramKV...)
	}
}

// MakeGetRolesOfUserEndpoint creates an endpoint for GetRolesOfUser
func MakeGetRolesOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRolesOfUser(ctx, m["realm"], m["userID"])
	}
}

// MakeGetGroupsOfUserEndpoint creates an endpoint for GetGroupsOfUser
func MakeGetGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetGroupsOfUser(ctx, m["realm"], m["userID"])
	}
}

// MakeSetGroupsToUserEndpoint creates an endpoint for SetGroupsToUser
func MakeSetGroupsToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var groupIDs []string
		if err := json.Unmarshal([]byte(m["body"]), &groupIDs); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		return nil, component.SetGroupsToUser(ctx, m["realm"], m["userID"], groupIDs)
	}
}

// MakeGetAvailableTrustIDGroupsEndpoint creates an endpoint for GetAvailableTrustIDGroups
func MakeGetAvailableTrustIDGroupsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAvailableTrustIDGroups(ctx, m["realm"])
	}
}

// MakeGetTrustIDGroupsOfUserEndpoint creates an endpoint for GetTrustIDGroupsOfUser
func MakeGetTrustIDGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetTrustIDGroupsOfUser(ctx, m["realm"], m["userID"])
	}
}

// MakeSetTrustIDGroupsToUserEndpoint creates an endpoint for SetTrustIDGroupsToUser
func MakeSetTrustIDGroupsToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var groupNames []string

		if err := json.Unmarshal([]byte(m["body"]), &groupNames); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		return nil, component.SetTrustIDGroupsToUser(ctx, m["realm"], m["userID"], groupNames)
	}
}

// MakeGetUserAccountStatusEndpoint creates an endpoint for GetUserAccountStatus
func MakeGetUserAccountStatusEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUserAccountStatus(ctx, m["realm"], m["userID"])
	}
}

// MakeGetClientRolesForUserEndpoint creates an endpoint for GetClientRolesForUser
func MakeGetClientRolesForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClientRolesForUser(ctx, m["realm"], m["userID"], m["clientID"])
	}
}

// MakeAddClientRolesToUserEndpoint creates an endpoint for AddClientRolesToUser
func MakeAddClientRolesToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var roles []api.RoleRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &roles); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		for _, role := range roles {
			if err = role.Validate(); err != nil {
				return nil, err
			}
		}

		return nil, component.AddClientRolesToUser(ctx, m["realm"], m["userID"], m["clientID"], roles)
	}
}

// MakeResetPasswordEndpoint creates an endpoint for ResetPassword
func MakeResetPasswordEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var password api.PasswordRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &password); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = password.Validate(); err != nil {
			return nil, err
		}

		pwd, err := component.ResetPassword(ctx, m["realm"], m["userID"], password)
		if pwd != "" {
			return pwd, err
		}
		return nil, err
	}
}

// MakeExecuteActionsEmailEndpoint creates an endpoint for ExecuteActionsEmail
func MakeExecuteActionsEmailEndpoint(component Component) cs.Endpoint {
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
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		for _, action := range actions {
			if err = action.Validate(); err != nil {
				return nil, err
			}
		}

		return nil, component.ExecuteActionsEmail(ctx, m["realm"], m["userID"], actions, paramKV...)
	}
}

// MakeSendNewEnrolmentCodeEndpoint creates an endpoint for SendNewEnrolmentCode
func MakeSendNewEnrolmentCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		code, err := component.SendNewEnrolmentCode(ctx, m["realm"], m["userID"])
		return map[string]string{"code": code}, err
	}
}

// MakeSendReminderEmailEndpoint creates an endpoint for SendReminderEmail
func MakeSendReminderEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{"client_id", "redirect_uri", "lifespan"} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		return nil, component.SendReminderEmail(ctx, m["realm"], m["userID"], paramKV...)
	}
}

// MakeResetSmsCounterEndpoint creates an endpoint for ResetSmsCounter
func MakeResetSmsCounterEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.ResetSmsCounter(ctx, m["realm"], m["userID"])
	}
}

// MakeCreateRecoveryCodeEndpoint creates an endpoint for MakeCreateRecoveryCode
func MakeCreateRecoveryCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.CreateRecoveryCode(ctx, m["realm"], m["userID"])
	}
}

// MakeGetCredentialsForUserEndpoint creates an endpoint for GetCredentialsForUser
func MakeGetCredentialsForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetCredentialsForUser(ctx, m["realm"], m["userID"])
	}
}

// MakeDeleteCredentialsForUserEndpoint creates an endpoint for DeleteCredentialsForUser
func MakeDeleteCredentialsForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteCredentialsForUser(ctx, m["realm"], m["userID"], m["credentialID"])
	}
}

// MakeClearUserLoginFailures creates an endpoint for ClearUserLoginFailures
func MakeClearUserLoginFailures(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.ClearUserLoginFailures(ctx, m["realm"], m["userID"])
	}
}

// MakeGetAttackDetectionStatus creates an endpoint for GetAttackDetectionStatus
func MakeGetAttackDetectionStatus(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAttackDetectionStatus(ctx, m["realm"], m["userID"])
	}
}

// MakeGetRolesEndpoint creates an endpoint for GetRoles
func MakeGetRolesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRoles(ctx, m["realm"])
	}
}

// MakeGetRoleEndpoint creates an endpoint for GetRole
func MakeGetRoleEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRole(ctx, m["realm"], m["roleID"])
	}
}

// MakeGetClientRolesEndpoint creates an endpoint for GetClientRoles
func MakeGetClientRolesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClientRoles(ctx, m["realm"], m["clientID"])
	}
}

// MakeCreateClientRoleEndpoint creates an endpoint for CreateClientRole
func MakeCreateClientRoleEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var role api.RoleRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &role); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = role.Validate(); err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateClientRole(ctx, m["realm"], m["clientID"], role)

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

// MakeGetGroupsEndpoint creates an endpoint for GetGroups
func MakeGetGroupsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetGroups(ctx, m["realm"])
	}
}

// MakeCreateGroupEndpoint makes the endpoint to create a group.
func MakeCreateGroupEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var group api.GroupRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &group); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = group.Validate(); err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateGroup(ctx, m["realm"], group)

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

// MakeDeleteGroupEndpoint creates an endpoint for DeleteGroup
func MakeDeleteGroupEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteGroup(ctx, m["realm"], m["groupID"])
	}
}

// MakeGetAuthorizationsEndpoint creates an endpoint for GetAuthorizations
func MakeGetAuthorizationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAuthorizations(ctx, m["realm"], m["groupID"])
	}
}

// MakeUpdateAuthorizationsEndpoint creates an endpoint for UpdateAuthorizations
func MakeUpdateAuthorizationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var authorizations api.AuthorizationsRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &authorizations); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		return nil, component.UpdateAuthorizations(ctx, m["realm"], m["groupID"], authorizations)
	}
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return component.GetActions(ctx)
	}
}

// MakeGetRealmCustomConfigurationEndpoint creates an endpoint for GetRealmCustomConfiguration
func MakeGetRealmCustomConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRealmCustomConfiguration(ctx, m["realm"])
	}
}

// MakeUpdateRealmCustomConfigurationEndpoint creates an endpoint for UpdateRealmCustomConfiguration
func MakeUpdateRealmCustomConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		configJSON := []byte(m["body"])

		var customConfig api.RealmCustomConfiguration

		if err = json.Unmarshal(configJSON, &customConfig); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = customConfig.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateRealmCustomConfiguration(ctx, m["realm"], customConfig)
	}
}

// MakeGetRealmAdminConfigurationEndpoint creates an endpoint for GetRealmAdminConfiguration
func MakeGetRealmAdminConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return component.GetRealmAdminConfiguration(ctx, m["realm"])
	}
}

// MakeUpdateRealmAdminConfigurationEndpoint creates an endpoint for UpdateRealmAdminConfiguration
func MakeUpdateRealmAdminConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		configJSON := m["body"]

		var adminConfig api.RealmAdminConfiguration

		if err = json.Unmarshal([]byte(configJSON), &adminConfig); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = adminConfig.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateRealmAdminConfiguration(ctx, m["realm"], adminConfig)
	}
}

// MakeGetRealmBackOfficeConfigurationEndpoint creates an endpoint for GetRealmBackOfficeConfiguration
func MakeGetRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var groupName = m["groupName"]
		if groupName == "" {
			return nil, errorhandler.CreateMissingParameterError(msg.GroupName)
		}

		return component.GetRealmBackOfficeConfiguration(ctx, m["realm"], groupName)
	}
}

// MakeUpdateRealmBackOfficeConfigurationEndpoint creates an endpoint for UpdateRealmBackOfficeConfiguration
func MakeUpdateRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var boConf, err = api.NewBackOfficeConfigurationFromJSON(m["body"])
		if err != nil {
			return nil, err
		}
		var groupName = m["groupName"]
		if groupName == "" {
			return nil, errorhandler.CreateMissingParameterError(msg.GroupName)
		}

		return nil, component.UpdateRealmBackOfficeConfiguration(ctx, m["realm"], groupName, boConf)
	}
}

// MakeGetUserRealmBackOfficeConfigurationEndpoint creates an endpoint for GetUserRealmBackOfficeConfiguration
func MakeGetUserRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUserRealmBackOfficeConfiguration(ctx, m["realm"])
	}
}

// MakeLinkShadowUserEndpoint makes the endpoint to create a shadow user.
func MakeLinkShadowUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var fedID api.FederatedIdentityRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &fedID); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = fedID.Validate(); err != nil {
			return nil, err
		}

		err = component.LinkShadowUser(ctx, m["realm"], m["userID"], m["provider"], fedID)

		if err != nil {
			return nil, err
		}

		return nil, nil
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
