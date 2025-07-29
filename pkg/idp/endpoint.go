package idp

import (
	"context"
	"encoding/json"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"

	"github.com/go-kit/kit/endpoint"
)

// Endpoints wraps a service behind a set of endpoints.
type Endpoints struct {
	GetActions             endpoint.Endpoint
	GetIdentityProvider    endpoint.Endpoint
	CreateIdentityProvider endpoint.Endpoint
	UpdateIdentityProvider endpoint.Endpoint
	DeleteIdentityProvider endpoint.Endpoint
}

// MakeCreateIdentityProviderEndpoint creates an endpoint for CreateIdentityProvider
func MakeCreateIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {

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
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return component.GetIdentityProvider(ctx, m[prmRealm], m[prmProvider])
	}
}

// MakeUpdateIdentityProviderEndpoint creates an endpoint for UpdateIdentityProvider
func MakeUpdateIdentityProviderEndpoint(component Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
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
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)

		return nil, component.DeleteIdentityProvider(ctx, m[prmRealm], m[prmProvider])
	}
}
