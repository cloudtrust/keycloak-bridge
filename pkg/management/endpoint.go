package management

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	commonhttp "github.com/cloudtrust/common-service/http"
	api "github.com/cloudtrust/keycloak-bridge/api/management"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetRealms          endpoint.Endpoint
	GetRealm           endpoint.Endpoint
	GetClient          endpoint.Endpoint
	GetClients         endpoint.Endpoint
	GetRequiredActions endpoint.Endpoint

	DeleteUser                  endpoint.Endpoint
	GetUser                     endpoint.Endpoint
	GetUserProof                endpoint.Endpoint
	GetUserHisto                endpoint.Endpoint
	UpdateUser                  endpoint.Endpoint
	LockUser                    endpoint.Endpoint
	UnlockUser                  endpoint.Endpoint
	GetUsers                    endpoint.Endpoint
	CreateUser                  endpoint.Endpoint
	GetRolesOfUser              endpoint.Endpoint
	GetGroupsOfUser             endpoint.Endpoint
	AddGroupToUser              endpoint.Endpoint
	DeleteGroupForUser          endpoint.Endpoint
	GetAvailableTrustIDGroups   endpoint.Endpoint
	GetTrustIDGroupsOfUser      endpoint.Endpoint
	SetTrustIDGroupsToUser      endpoint.Endpoint
	GetUserChecks               endpoint.Endpoint
	GetUserAccountStatus        endpoint.Endpoint
	GetUserAccountStatusByEmail endpoint.Endpoint
	GetClientRoleForUser        endpoint.Endpoint
	AddClientRoleToUser         endpoint.Endpoint

	ResetPassword                  endpoint.Endpoint
	ExecuteActionsEmail            endpoint.Endpoint
	SendSmsCode                    endpoint.Endpoint
	SendOnboardingEmail            endpoint.Endpoint
	SendReminderEmail              endpoint.Endpoint
	ResetSmsCounter                endpoint.Endpoint
	CreateRecoveryCode             endpoint.Endpoint
	CreateActivationCode           endpoint.Endpoint
	GetCredentialsForUser          endpoint.Endpoint
	DeleteCredentialsForUser       endpoint.Endpoint
	ResetCredentialFailuresForUser endpoint.Endpoint
	ClearUserLoginFailures         endpoint.Endpoint
	GetAttackDetectionStatus       endpoint.Endpoint

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
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetRealms(ctx)
	}
}

// MakeGetRealmEndpoint makes the Realm endpoint to retrieve a realm.
func MakeGetRealmEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRealm(ctx, m[prmRealm])
	}
}

// MakeGetClientEndpoint creates an endpoint for GetClient
func MakeGetClientEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClient(ctx, m[prmRealm], m[prmClientID])
	}
}

// MakeGetClientsEndpoint creates an endpoint for GetClients
func MakeGetClientsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClients(ctx, m[prmRealm])
	}
}

// MakeGetRequiredActionsEndpoint creates an endpoint for GetRequiredActions
func MakeGetRequiredActionsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRequiredActions(ctx, m[prmRealm])
	}
}

// MakeCreateUserEndpoint makes the endpoint to create a user.
func MakeCreateUserEndpoint(component Component, logger keycloakb.Logger) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, err
		}

		if user.Groups == nil || len(*user.Groups) == 0 {
			return nil, errorhandler.CreateMissingParameterError(msg.Groups)
		}

		var generateUsername = false
		if prmGenerateUsername, ok := m[prmQryGenUsername]; ok {
			generateUsername = strings.ToLower(prmGenerateUsername) == "true"
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateUser(ctx, m[prmRealm], user, generateUsername)

		if err != nil {
			return nil, err
		}

		url, err := convertLocationURL(keycloakLocation, m[reqScheme], m[reqHost])
		if err != nil {
			logger.Warn(ctx, "msg", "Invalid location", "location", keycloakLocation, "err", err.Error())
		}

		return LocationHeader{
			URL: url,
		}, nil
	}
}

// MakeDeleteUserEndpoint creates an endpoint for DeleteUser
func MakeDeleteUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetUserEndpoint creates an endpoint for GetUser
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetUserProofEndpoint creates an endpoint for GetUserProof
func MakeGetUserProofEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var res, err = component.GetUserProof(ctx, m[prmRealm], m[prmUserID])
		if err != nil {
			return nil, err
		}
		return commonhttp.GenericResponse{
			StatusCode:  200,
			MimeContent: &res,
		}, nil
	}
}

// MakeGetUserHistoEndpoint creates an endpoint for GetUserHisto
func MakeGetUserHistoEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var res, err = component.GetUserHisto(ctx, m[prmRealm], m[prmUserID])
		if err != nil {
			return nil, err
		}
		return res, nil
	}
}

// MakeUpdateUserEndpoint creates an endpoint for UpdateUser
func MakeUpdateUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var user api.UpdatableUserRepresentation

		if err := json.Unmarshal([]byte(m[reqBody]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + msg.Body)
		}

		if err := user.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateUser(ctx, m[prmRealm], m[prmUserID], user)
	}
}

// MakeLockUserEndpoint creates an endpoint for LockUser
func MakeLockUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.LockUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeUnlockUserEndpoint creates an endpoint for LockUser
func MakeUnlockUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.UnlockUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetUsersEndpoint creates an endpoint for GetUsers
func MakeGetUsersEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{prmQryEmail, prmQryFirstName, prmQryLastName, prmQryUserName, prmQrySearch, prmQryFirst, prmQryMax} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		_, ok := m[prmQryGroupIDs]
		if !ok {
			return nil, errorhandler.CreateMissingParameterError(msg.GroupIDs)
		}

		groupIDs := strings.Split(m[prmQryGroupIDs], ",")

		return component.GetUsers(ctx, m[prmRealm], groupIDs, paramKV...)
	}
}

// MakeGetRolesOfUserEndpoint creates an endpoint for GetRolesOfUser
func MakeGetRolesOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRolesOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetGroupsOfUserEndpoint creates an endpoint for GetGroupsOfUser
func MakeGetGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetGroupsOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeAddGroupToUserEndpoint creates an endpoint for AddGroupToUser
func MakeAddGroupToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.AddGroupToUser(ctx, m[prmRealm], m[prmUserID], m[prmGroupID])
	}
}

// MakeDeleteGroupForUserEndpoint creates an endpoint for DeleteGroupForUser
func MakeDeleteGroupForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteGroupForUser(ctx, m[prmRealm], m[prmUserID], m[prmGroupID])
	}
}

// MakeGetAvailableTrustIDGroupsEndpoint creates an endpoint for GetAvailableTrustIDGroups
func MakeGetAvailableTrustIDGroupsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAvailableTrustIDGroups(ctx, m[prmRealm])
	}
}

// MakeGetTrustIDGroupsOfUserEndpoint creates an endpoint for GetTrustIDGroupsOfUser
func MakeGetTrustIDGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetTrustIDGroupsOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeSetTrustIDGroupsToUserEndpoint creates an endpoint for SetTrustIDGroupsToUser
func MakeSetTrustIDGroupsToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var groupNames []string

		if err := json.Unmarshal([]byte(m[reqBody]), &groupNames); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		return nil, component.SetTrustIDGroupsToUser(ctx, m[prmRealm], m[prmUserID], groupNames)
	}
}

// MakeGetUserChecksEndpoint creates an endpoint for GetUserChecks
func MakeGetUserChecksEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUserChecks(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetUserAccountStatusEndpoint creates an endpoint for GetUserAccountStatus
func MakeGetUserAccountStatusEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUserAccountStatus(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetUserAccountStatusByEmailEndpoint creates an endpoint for GetUserAccountStatusByEmail
func MakeGetUserAccountStatusByEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var email = m[prmQryEmail]

		if email == "" {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + prmQryEmail)
		}

		return component.GetUserAccountStatusByEmail(ctx, m[prmRealm], email)
	}
}

// MakeGetClientRolesForUserEndpoint creates an endpoint for GetClientRolesForUser
func MakeGetClientRolesForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClientRolesForUser(ctx, m[prmRealm], m[prmUserID], m[prmClientID])
	}
}

// MakeAddClientRolesToUserEndpoint creates an endpoint for AddClientRolesToUser
func MakeAddClientRolesToUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var roles []api.RoleRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &roles); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		for _, role := range roles {
			if err = role.Validate(); err != nil {
				return nil, err
			}
		}

		return nil, component.AddClientRolesToUser(ctx, m[prmRealm], m[prmUserID], m[prmClientID], roles)
	}
}

// MakeResetPasswordEndpoint creates an endpoint for ResetPassword
func MakeResetPasswordEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var password api.PasswordRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &password); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = password.Validate(); err != nil {
			return nil, err
		}

		pwd, err := component.ResetPassword(ctx, m[prmRealm], m[prmUserID], password)
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
		for _, key := range []string{prmQryClientID, prmQryRedirectURI, prmQryLifespan} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		//extract the actions
		var actions []api.RequiredAction

		if err = json.Unmarshal([]byte(m[reqBody]), &actions); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		for _, action := range actions {
			if err = action.Validate(); err != nil {
				return nil, err
			}
		}

		return nil, component.ExecuteActionsEmail(ctx, m[prmRealm], m[prmUserID], actions, paramKV...)
	}
}

// MakeSendSmsCodeEndpoint creates an endpoint for SendSmsCode
func MakeSendSmsCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		code, err := component.SendSmsCode(ctx, m[prmRealm], m[prmUserID])
		return map[string]string{"code": code}, err
	}
}

// MakeSendOnboardingEmailEndpoint creates an endpoint for SendOnboardingEmail
func MakeSendOnboardingEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var reminder = false
		if value, ok := m[prmQryReminder]; ok {
			reminder = strings.ToLower(value) == "true"
		}

		var customerRealmName = m[prmRealm]
		if value, ok := m[prmQryRealm]; ok && value != "" {
			customerRealmName = value
		}

		return nil, component.SendOnboardingEmail(ctx, m[prmRealm], m[prmUserID], customerRealmName, reminder)
	}
}

// MakeSendReminderEmailEndpoint creates an endpoint for SendReminderEmail
func MakeSendReminderEmailEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var paramKV []string
		for _, key := range []string{prmQryClientID, prmQryRedirectURI, prmQryLifespan} {
			if m[key] != "" {
				paramKV = append(paramKV, key, m[key])
			}
		}

		return nil, component.SendReminderEmail(ctx, m[prmRealm], m[prmUserID], paramKV...)
	}
}

// MakeResetSmsCounterEndpoint creates an endpoint for ResetSmsCounter
func MakeResetSmsCounterEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.ResetSmsCounter(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeCreateRecoveryCodeEndpoint creates an endpoint for MakeCreateRecoveryCode
func MakeCreateRecoveryCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.CreateRecoveryCode(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeCreateActivationCodeEndpoint creates an endpoint for MakeCreateActivationCode
func MakeCreateActivationCodeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.CreateActivationCode(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetCredentialsForUserEndpoint creates an endpoint for GetCredentialsForUser
func MakeGetCredentialsForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetCredentialsForUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeDeleteCredentialsForUserEndpoint creates an endpoint for DeleteCredentialsForUser
func MakeDeleteCredentialsForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteCredentialsForUser(ctx, m[prmRealm], m[prmUserID], m[prmCredentialID])
	}
}

// MakeResetCredentialFailuresForUserEndpoint creates an endpoint for UnlockCredentialForUser
func MakeResetCredentialFailuresForUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.ResetCredentialFailuresForUser(ctx, m[prmRealm], m[prmUserID], m[prmCredentialID])
	}
}

// MakeClearUserLoginFailures creates an endpoint for ClearUserLoginFailures
func MakeClearUserLoginFailures(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.ClearUserLoginFailures(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetAttackDetectionStatus creates an endpoint for GetAttackDetectionStatus
func MakeGetAttackDetectionStatus(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAttackDetectionStatus(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetRolesEndpoint creates an endpoint for GetRoles
func MakeGetRolesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRoles(ctx, m[prmRealm])
	}
}

// MakeGetRoleEndpoint creates an endpoint for GetRole
func MakeGetRoleEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRole(ctx, m[prmRealm], m[prmRoleID])
	}
}

// MakeGetClientRolesEndpoint creates an endpoint for GetClientRoles
func MakeGetClientRolesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetClientRoles(ctx, m[prmRealm], m[prmClientID])
	}
}

// MakeCreateClientRoleEndpoint creates an endpoint for CreateClientRole
func MakeCreateClientRoleEndpoint(component Component, logger keycloakb.Logger) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var role api.RoleRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &role); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = role.Validate(); err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateClientRole(ctx, m[prmRealm], m[prmClientID], role)

		if err != nil {
			return nil, err
		}

		url, err := convertLocationURL(keycloakLocation, m[reqScheme], m[reqHost])
		if err != nil {
			logger.Warn(ctx, "msg", "Invalid location", "location", keycloakLocation, "err", err.Error())
		}

		return LocationHeader{
			URL: url,
		}, nil
	}
}

// MakeGetGroupsEndpoint creates an endpoint for GetGroups
func MakeGetGroupsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetGroups(ctx, m[prmRealm])
	}
}

// MakeCreateGroupEndpoint makes the endpoint to create a group.
func MakeCreateGroupEndpoint(component Component, logger keycloakb.Logger) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var group api.GroupRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &group); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = group.Validate(); err != nil {
			return nil, err
		}

		var keycloakLocation string
		keycloakLocation, err = component.CreateGroup(ctx, m[prmRealm], group)

		if err != nil {
			return nil, err
		}

		url, err := convertLocationURL(keycloakLocation, m[reqScheme], m[reqHost])
		if err != nil {
			logger.Warn(ctx, "msg", "Invalid location", "location", keycloakLocation, "err", err.Error())
		}

		return LocationHeader{
			URL: url,
		}, nil
	}
}

// MakeDeleteGroupEndpoint creates an endpoint for DeleteGroup
func MakeDeleteGroupEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteGroup(ctx, m[prmRealm], m[prmGroupID])
	}
}

// MakeGetAuthorizationsEndpoint creates an endpoint for GetAuthorizations
func MakeGetAuthorizationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetAuthorizations(ctx, m[prmRealm], m[prmGroupID])
	}
}

// MakeUpdateAuthorizationsEndpoint creates an endpoint for UpdateAuthorizations
func MakeUpdateAuthorizationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var authorizations api.AuthorizationsRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &authorizations); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		return nil, component.UpdateAuthorizations(ctx, m[prmRealm], m[prmGroupID], authorizations)
	}
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return component.GetActions(ctx)
	}
}

// MakeGetRealmCustomConfigurationEndpoint creates an endpoint for GetRealmCustomConfiguration
func MakeGetRealmCustomConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRealmCustomConfiguration(ctx, m[prmRealm])
	}
}

// MakeUpdateRealmCustomConfigurationEndpoint creates an endpoint for UpdateRealmCustomConfiguration
func MakeUpdateRealmCustomConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		configJSON := []byte(m[reqBody])

		var customConfig api.RealmCustomConfiguration

		if err = json.Unmarshal(configJSON, &customConfig); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = customConfig.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateRealmCustomConfiguration(ctx, m[prmRealm], customConfig)
	}
}

// MakeGetRealmAdminConfigurationEndpoint creates an endpoint for GetRealmAdminConfiguration
func MakeGetRealmAdminConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return component.GetRealmAdminConfiguration(ctx, m[prmRealm])
	}
}

// MakeUpdateRealmAdminConfigurationEndpoint creates an endpoint for UpdateRealmAdminConfiguration
func MakeUpdateRealmAdminConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		configJSON := m[reqBody]

		var adminConfig api.RealmAdminConfiguration

		if err = json.Unmarshal([]byte(configJSON), &adminConfig); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = adminConfig.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateRealmAdminConfiguration(ctx, m[prmRealm], adminConfig)
	}
}

// MakeGetRealmBackOfficeConfigurationEndpoint creates an endpoint for GetRealmBackOfficeConfiguration
func MakeGetRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var groupName = m[prmQryGroupName]
		if groupName == "" {
			return nil, errorhandler.CreateMissingParameterError(msg.GroupName)
		}

		return component.GetRealmBackOfficeConfiguration(ctx, m[prmRealm], groupName)
	}
}

// MakeUpdateRealmBackOfficeConfigurationEndpoint creates an endpoint for UpdateRealmBackOfficeConfiguration
func MakeUpdateRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var boConf, err = api.NewBackOfficeConfigurationFromJSON(m[reqBody])
		if err != nil {
			return nil, err
		}
		var groupName = m[prmQryGroupName]
		if groupName == "" {
			return nil, errorhandler.CreateMissingParameterError(msg.GroupName)
		}

		return nil, component.UpdateRealmBackOfficeConfiguration(ctx, m[prmRealm], groupName, boConf)
	}
}

// MakeGetUserRealmBackOfficeConfigurationEndpoint creates an endpoint for GetUserRealmBackOfficeConfiguration
func MakeGetUserRealmBackOfficeConfigurationEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUserRealmBackOfficeConfiguration(ctx, m[prmRealm])
	}
}

// MakeLinkShadowUserEndpoint makes the endpoint to create a shadow user.
func MakeLinkShadowUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var fedID api.FederatedIdentityRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &fedID); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = fedID.Validate(); err != nil {
			return nil, err
		}

		err = component.LinkShadowUser(ctx, m[prmRealm], m[prmUserID], m[prmProvider], fedID)

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
