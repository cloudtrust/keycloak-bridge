package validation

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	GetUser                  endpoint.Endpoint
	UpdateUser               endpoint.Endpoint
	UpdateUserAccreditations endpoint.Endpoint
	CreateCheck              endpoint.Endpoint
	GetGroupsOfUser          endpoint.Endpoint
	GetRolesOfUser           endpoint.Endpoint
	//CreatePendingCheck       endpoint.Endpoint
}

// UserProfileCache interface
type UserProfileCache interface {
	GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error)
}

// NewEndpoints creates an Endpoints instance
func NewEndpoints(component Component, profileCache UserProfileCache, endpointWrapper func(endpoint cs.Endpoint, name string) endpoint.Endpoint) Endpoints {
	return Endpoints{
		GetUser:                  endpointWrapper(MakeGetUserEndpoint(component), "get_user"),
		UpdateUser:               endpointWrapper(MakeUpdateUserEndpoint(component, profileCache), "update_user"),
		UpdateUserAccreditations: endpointWrapper(MakeUpdateUserAccreditationsEndpoint(component), "update_user_accreditations"),
		GetGroupsOfUser:          endpointWrapper(MakeGetGroupsOfUserEndpoint(component), "get_user_groups"),
		GetRolesOfUser:           endpointWrapper(MakeGetRolesOfUserEndpoint(component), "get_user_roles"),
	}
}

// MakeGetUserEndpoint endpoint creation
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeUpdateUserEndpoint endpoint creation
func MakeUpdateUserEndpoint(component Component, profileCache UserProfileCache) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var realm = m[prmRealm]
		var err error

		var user api.UserRepresentation
		if err = json.Unmarshal([]byte(m[reqBody]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = user.Validate(ctx, profileCache, realm); err != nil {
			return nil, err
		}

		txnID, ok := m[prmTxnID]
		if !ok {
			return nil, component.UpdateUser(ctx, realm, m[prmUserID], user, nil)
		}

		return nil, component.UpdateUser(ctx, realm, m[prmUserID], user, &txnID)
	}
}

// MakeUpdateUserAccreditationsEndpoint endpoint creation
func MakeUpdateUserAccreditationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var accreds []api.AccreditationRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &accreds); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		for _, accred := range accreds {
			if err = accred.Validate(); err != nil {
				return nil, err
			}
		}

		return nil, component.UpdateUserAccreditations(ctx, m[prmRealm], m[prmUserID], accreds)
	}
}

// MakeGetGroupsOfUserEndpoint creates an endpoint for GetGroupsOfUser
func MakeGetGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetGroupsOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeGetRolesOfUserEndpoint creates an endpoint for GetRolesOfUser
func MakeGetRolesOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetRolesOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}
