package components

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/components"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions      endpoint.Endpoint
	GetComponents   endpoint.Endpoint
	CreateComponent endpoint.Endpoint
	UpdateComponent endpoint.Endpoint
}

// MakeGetComponentEndpoint creates an endpoint for GetComponent
func MakeGetComponentsEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		var providerType *string
		if value, ok := m[prmQryType]; ok {
			providerType = &value
		}

		return component.GetComponents(ctx, m[prmRealmName], providerType)
	}
}

// MakeCreateComponentEndpoint creates an endpoint for CreateComponent
func MakeCreateComponentEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {

		var m = req.(map[string]string)
		var err error

		var comp api.ComponentRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &comp); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = comp.Validate(); err != nil {
			return nil, err
		}

		return component.CreateComponent(ctx, m[prmRealmName], comp), nil
	}
}

// MakeUpdateComponentEndpoint creates an endpoint for UpdateComponent
func MakeUpdateComponentEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		var err error

		var comp api.ComponentRepresentation

		if err = json.Unmarshal([]byte(m[reqBody]), &comp); err != nil {
			return nil, errorhandler.CreateBadRequestError(msg.MsgErrInvalidParam + "." + msg.Body)
		}

		if err = comp.Validate(); err != nil {
			return nil, err
		}

		return nil, component.UpdateComponent(ctx, m[prmRealmName], m[prmComponentID], comp)
	}
}
