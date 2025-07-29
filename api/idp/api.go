package apiidp

import (
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// IdentityProviderRepresentation struct
type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool                   `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string                 `json:"alias,omitempty"`
	AuthenticateByDefault     *bool                   `json:"authenticateByDefault,omitempty"`
	Config                    *map[string]interface{} `json:"config,omitempty"`
	DisplayName               *string                 `json:"displayName,omitempty"`
	Enabled                   *bool                   `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string                 `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalID                *string                 `json:"internalId,omitempty"`
	LinkOnly                  *bool                   `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string                 `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderID                *string                 `json:"providerId,omitempty"`
	StoreToken                *bool                   `json:"storeToken,omitempty"`
	TrustEmail                *bool                   `json:"trustEmail,omitempty"`
}

// ConvertToAPIIdentityProvider creates an API IdentityProviderRepresentation from a KC IdentityProviderRepresentation
func ConvertToAPIIdentityProvider(idp kc.IdentityProviderRepresentation) IdentityProviderRepresentation {
	return IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  idp.AddReadTokenRoleOnCreate,
		Alias:                     idp.Alias,
		AuthenticateByDefault:     idp.AuthenticateByDefault,
		Config:                    idp.Config,
		DisplayName:               idp.DisplayName,
		Enabled:                   idp.Enabled,
		FirstBrokerLoginFlowAlias: idp.FirstBrokerLoginFlowAlias,
		InternalID:                idp.InternalID,
		LinkOnly:                  idp.LinkOnly,
		PostBrokerLoginFlowAlias:  idp.PostBrokerLoginFlowAlias,
		ProviderID:                idp.ProviderID,
		StoreToken:                idp.StoreToken,
		TrustEmail:                idp.TrustEmail,
	}
}

// ConvertToKCIdentityProvider creates a KC IdentityProviderRepresentation from an API IdentityProviderRepresentation
func ConvertToKCIdentityProvider(idp IdentityProviderRepresentation) kc.IdentityProviderRepresentation {
	return kc.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  idp.AddReadTokenRoleOnCreate,
		Alias:                     idp.Alias,
		AuthenticateByDefault:     idp.AuthenticateByDefault,
		Config:                    idp.Config,
		DisplayName:               idp.DisplayName,
		Enabled:                   idp.Enabled,
		FirstBrokerLoginFlowAlias: idp.FirstBrokerLoginFlowAlias,
		InternalID:                idp.InternalID,
		LinkOnly:                  idp.LinkOnly,
		PostBrokerLoginFlowAlias:  idp.PostBrokerLoginFlowAlias,
		ProviderID:                idp.ProviderID,
		StoreToken:                idp.StoreToken,
		TrustEmail:                idp.TrustEmail,
	}
}

// Validate is a validator for IdentityProviderRepresentation
func (idp IdentityProviderRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp("alias", idp.Alias, constants.RegExpFederatedUsername, true).
		ValidateParameterRegExp("displayName", idp.DisplayName, constants.RegExpFederatedUsername, true).
		ValidateParameterRegExp("firstBrokerLoginFlowAlias", idp.FirstBrokerLoginFlowAlias, constants.RegExpFederatedUsername, true).
		ValidateParameterRegExp("internalId", idp.InternalID, constants.RegExpID, true).
		ValidateParameterRegExp("postBrokerLoginFlowAlias", idp.PostBrokerLoginFlowAlias, constants.RegExpFederatedUsername, true).
		ValidateParameterRegExp("providerId", idp.ProviderID, constants.RegExpFederatedUsername, true).
		Status()
}
