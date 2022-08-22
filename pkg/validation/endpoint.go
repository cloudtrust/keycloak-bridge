package validation

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	GetUser                  endpoint.Endpoint
	UpdateUser               endpoint.Endpoint
	UpdateUserAccreditations endpoint.Endpoint
	CreateCheck              endpoint.Endpoint
	GetGroupsOfUser          endpoint.Endpoint
	//CreatePendingCheck       endpoint.Endpoint
}

// MakeGetUserEndpoint endpoint creation
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetUser(ctx, m[prmRealm], m[prmUserID])
	}
}

// MakeUpdateUserEndpoint endpoint creation
func MakeUpdateUserEndpoint(component Component) cs.Endpoint {
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

		txnID, ok := m[prmTxnID]
		if !ok {
			return nil, component.UpdateUser(ctx, m[prmRealm], m[prmUserID], user, nil)
		}

		return nil, component.UpdateUser(ctx, m[prmRealm], m[prmUserID], user, &txnID)
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
