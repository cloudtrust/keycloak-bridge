package validation

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/validation"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints for self service
type Endpoints struct {
	GetUser     endpoint.Endpoint
	UpdateUser  endpoint.Endpoint
	CreateCheck endpoint.Endpoint
}

// MakeGetUserEndpoint endpoint creation
func MakeGetUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var user = m["userID"]
		return component.GetUser(ctx, user)
	}
}

// MakeGetUserEndpoint endpoint creation
func MakeUpdateUserEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var user api.UserRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &user); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = user.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		return nil, component.UpdateUser(ctx, m["userID"], user)
	}
}

// MakeCreateCheckEndpoint endpoint creation
func MakeCreateCheckEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var check api.CheckRepresentation

		if err = json.Unmarshal([]byte(m["body"]), &check); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = check.Validate(); err != nil {
			return nil, errorhandler.CreateBadRequestError(err.Error())
		}

		return nil, component.CreateCheck(ctx, m["userID"], check)
	}
}
