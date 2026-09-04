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
		GetUser:                  endpointWrapper(makeGetUserEndpoint(component), "get_user"),
		UpdateUser:               endpointWrapper(makeUpdateUserEndpoint(component, profileCache), "update_user"),
		UpdateUserAccreditations: endpointWrapper(makeUpdateUserAccreditationsEndpoint(component), "update_user_accreditations"),
		GetGroupsOfUser:          endpointWrapper(makeGetGroupsOfUserEndpoint(component), "get_user_groups"),
		GetRolesOfUser:           endpointWrapper(makeGetRolesOfUserEndpoint(component), "get_user_roles"),
	}
}

func getOptionalParam(m map[string]string, key string) *string {
	if val, ok := m[key]; ok {
		return &val
	}
	return nil
}

// makeGetUserEndpoint endpoint creation
func makeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return component.GetUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// makeUpdateUserEndpoint endpoint creation
func makeUpdateUserEndpoint(component Component, profileCache UserProfileCache) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
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

		txnID := getOptionalParam(m, prmTxnID)
		return nil, component.UpdateUser(ctx, realm, m[prmUserID], user, txnID)
	}
}

// makeUpdateUserAccreditationsEndpoint endpoint creation
func makeUpdateUserAccreditationsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
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

		sponsor := getOptionalParam(m, prmSponsor)
		return nil, component.UpdateUserAccreditations(ctx, m[prmRealm], m[prmUserID], accreds, sponsor)
	}
}

// makeGetGroupsOfUserEndpoint creates an endpoint for GetGroupsOfUser
func makeGetGroupsOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return component.GetGroupsOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// makeGetRolesOfUserEndpoint creates an endpoint for GetRolesOfUser
func makeGetRolesOfUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req any) (any, error) {
		var m = req.(map[string]string)

		return component.GetRolesOfUser(ctx, m[prmRealm], m[prmUserID])
	}
}
