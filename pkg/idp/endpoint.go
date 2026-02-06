package idp

import (
	"context"
	"encoding/json"
	"fmt"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	commonhttp "github.com/cloudtrust/common-service/v2/http"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions                   endpoint.Endpoint
	GetIdentityProvider          endpoint.Endpoint
	CreateIdentityProvider       endpoint.Endpoint
	UpdateIdentityProvider       endpoint.Endpoint
	DeleteIdentityProvider       endpoint.Endpoint
	GetIdentityProviderMappers   endpoint.Endpoint
	CreateIdentityProviderMapper endpoint.Endpoint
	UpdateIdentityProviderMapper endpoint.Endpoint
	DeleteIdentityProviderMapper endpoint.Endpoint
	GetUsersWithAttribute        endpoint.Endpoint
	GetUser                      endpoint.Endpoint
	DeleteUser                   endpoint.Endpoint
	AddUserAttributes            endpoint.Endpoint
	DeleteUserAttributes         endpoint.Endpoint
	GetUserFederatedIdentities   endpoint.Endpoint
}

// NewEndpoints creates an Endpoints instance
func NewEndpoints(component Component, endpointUpdater func(endpoint cs.Endpoint, name string) endpoint.Endpoint) Endpoints {
	return Endpoints{
		GetIdentityProvider:          endpointUpdater(MakeGetIdentityProviderEndpoint(component), "get_identity_provider_endpoint"),
		CreateIdentityProvider:       endpointUpdater(MakeCreateIdentityProviderEndpoint(component), "create_identity_provider_endpoint"),
		UpdateIdentityProvider:       endpointUpdater(MakeUpdateIdentityProviderEndpoint(component), "update_identity_provider_endpoint"),
		DeleteIdentityProvider:       endpointUpdater(MakeDeleteIdentityProviderEndpoint(component), "delete_identity_provider_endpoint"),
		GetIdentityProviderMappers:   endpointUpdater(MakeGetIdentityProviderMappersEndpoint(component), "get_identity_provider_mappers_endpoint"),
		CreateIdentityProviderMapper: endpointUpdater(MakeCreateIdentityProviderMapperEndpoint(component), "create_identity_provider_mapper_endpoint"),
		UpdateIdentityProviderMapper: endpointUpdater(MakeUpdateIdentityProviderMapperEndpoint(component), "update_identity_provider_mapper_endpoint"),
		DeleteIdentityProviderMapper: endpointUpdater(MakeDeleteIdentityProviderMapperEndpoint(component), "delete_identity_provider_mapper_endpoint"),
		GetUsersWithAttribute:        endpointUpdater(MakeGetUsersWithAttributeEndpoint(component), "get_users_with_attribute_endpoint"),
		GetUser:                      endpointUpdater(MakeGetUserEndpoint(component), "get_user_endpoint"),
		DeleteUser:                   endpointUpdater(MakeDeleteUserEndpoint(component), "delete_user_endpoint"),
		AddUserAttributes:            endpointUpdater(MakeAddUserAttributesEndpoint(component), "add_user_attributes_endpoint"),
		DeleteUserAttributes:         endpointUpdater(MakeDeleteUserAttributesEndpoint(component), "delete_user_attributes_endpoint"),
		GetUserFederatedIdentities:   endpointUpdater(MakeGetUserFederatedIdentitiesEndpoint(component), "get_user_federated_identities_endpoint"),
	}
}

// MakeCreateIdentityProviderEndpoint creates an endpoint for CreateIdentityProvider
func MakeCreateIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {

		var m = req.(map[string]string)
		var err error

		var idp api.IdentityProviderRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &idp); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = idp.Validate(); err != nil {
			return nil, err
		}

		return component.CreateIdentityProvider(ctx, m[prmRealm], idp), nil
	}
}

// MakeGetIdentityProviderEndpoint creates an endpoint for GetIdentityProvider
func MakeGetIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return component.GetIdentityProvider(ctx, m[prmRealm], m[prmProvider])
	}
}

// MakeUpdateIdentityProviderEndpoint creates an endpoint for UpdateIdentityProvider
func MakeUpdateIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var err error

		var idp api.IdentityProviderRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &idp); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = idp.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateIdentityProvider(ctx, m[prmRealm], m[prmProvider], idp)
	}
}

// MakeDeleteIdentityProviderEndpoint creates an endpoint for DeleteIdentityProvider
func MakeDeleteIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteIdentityProvider(ctx, m[prmRealm], m[prmProvider])
	}
}

// MakeCreateIdentityProviderMapperEndpoint creates an endpoint for CreateIdentityProviderMapper
func MakeCreateIdentityProviderMapperEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var err error

		var mapper api.IdentityProviderMapperRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &mapper); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = mapper.Validate(); err != nil {
			return nil, err
		}

		return nil, component.CreateIdentityProviderMapper(ctx, m[prmRealm], m[prmProvider], mapper)
	}
}

// MakeGetIdentityProviderMappersEndpoint creates an endpoint for GetIdentityProviderMappers
func MakeGetIdentityProviderMappersEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return component.GetIdentityProviderMappers(ctx, m[prmRealm], m[prmProvider])
	}
}

// MakeUpdateIdentityProviderMapperEndpoint creates an endpoint for UpdateIdentityProviderMapper
func MakeUpdateIdentityProviderMapperEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var err error

		var mapper api.IdentityProviderMapperRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &mapper); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = mapper.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateIdentityProviderMapper(ctx, m[prmRealm], m[prmProvider], m[prmMapper], mapper)
	}
}

// MakeDeleteIdentityProviderMapperEndpoint creates an endpoint for DeleteIdentityProviderMapper
func MakeDeleteIdentityProviderMapperEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteIdentityProviderMapper(ctx, m[prmRealm], m[prmProvider], m[prmMapper])
	}
}

// MakeGetUsersWithAttributeEndpoint creates an endpoint for GetUsersWithAttribute
func MakeGetUsersWithAttributeEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var username *string
		if value, ok := m[prmUsername]; ok {
			username = &value
		}
		var groupName *string
		if value, ok := m[prmGroupName]; ok {
			groupName = &value
		}
		// Code is ready to handle multiple expected attributes, but for now we only support receiving one key-value pair
		var expectedAttributes map[string]string
		if attrKey, ok := m[prmAttribKey]; ok {
			if attrValue, ok := m[prmAttribValue]; ok {
				expectedAttributes = map[string]string{
					attrKey: attrValue,
				}
			} else {
				return nil, errorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + prmAttribValue)
			}
		} else if _, ok := m[prmAttribValue]; ok {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + prmAttribKey)
		}
		// At least one of username, groupName or expectedAttributes must be provided
		if username == nil && groupName == nil && len(expectedAttributes) == 0 {
			return nil, errorhandler.CreateBadRequestError(fmt.Sprintf("%s.%sor%sor%s", msg.MsgErrMissingParam, prmUsername, prmGroupName, prmAttribKey))
		}
		var needRoles *bool
		if needRolesStr, ok := m[prmNeedRoles]; ok {
			var needRolesVal = needRolesStr == "true"
			needRoles = &needRolesVal
		}
		return component.GetUsersWithAttribute(ctx, m[prmRealm], username, groupName, expectedAttributes, needRoles)
	}
}

// MakeGetUserEndpoint creates an endpoint for GetUser
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var grpName string
		if value, ok := m[prmGroupName]; ok {
			grpName = value
		} else {
			return nil, errorhandler.CreateMissingParameterError(prmGroupName)
		}
		return component.GetUser(ctx, m[prmRealm], m[prmUser], grpName)
	}
}

// MakeDeleteUserEndpoint creates an endpoint for DeleteUser
func MakeDeleteUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var grpName *string
		if value, ok := m[prmGroupName]; ok {
			grpName = &value
		}
		return nil, component.DeleteUser(ctx, m[prmRealm], m[prmUser], grpName)
	}
}

// MakeAddUserAttributesEndpoint creates an endpoint for AddUserAttributes
func MakeAddUserAttributesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var attributes map[string][]string
		if body, ok := m[reqBody]; ok {
			if err := json.Unmarshal([]byte(body), &attributes); err != nil {
				return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
			}
		} else {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + msg.Body)
		}
		return commonhttp.StatusNoContent{}, component.AddUserAttributes(ctx, m[prmRealm], m[prmUser], attributes)
	}
}

// MakeDeleteUserAttributesEndpoint creates an endpoint for DeleteUserAttributes
func MakeDeleteUserAttributesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		var keys []string
		if body, ok := m[reqBody]; ok {
			if err := json.Unmarshal([]byte(body), &keys); err != nil {
				return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
			}
		} else {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrMissingParam + "." + msg.Body)
		}
		return commonhttp.StatusNoContent{}, component.DeleteUserAttributes(ctx, m[prmRealm], m[prmUser], keys)
	}
}

// MakeGetUserFederatedIdentitiesEndpoint creates an endpoint for GetUserFederatedIdentities
func MakeGetUserFederatedIdentitiesEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)
		return component.GetUserFederatedIdentities(ctx, m[prmRealm], m[prmUser])
	}
}
