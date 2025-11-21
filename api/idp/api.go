package apiidp

import (
	"encoding/json"

	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// IdentityProviderRepresentation struct
type IdentityProviderRepresentation struct {
	AddReadTokenRoleOnCreate  *bool             `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                     *string           `json:"alias,omitempty"`
	AuthenticateByDefault     *bool             `json:"authenticateByDefault,omitempty"`
	Config                    map[string]string `json:"config,omitempty"`
	DisplayName               *string           `json:"displayName,omitempty"`
	Enabled                   *bool             `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias *string           `json:"firstBrokerLoginFlowAlias,omitempty"`
	HideOnLogin               *bool             `json:"hideOnLogin,omitempty"`
	InternalID                *string           `json:"internalId,omitempty"`
	LinkOnly                  *bool             `json:"linkOnly,omitempty"`
	PostBrokerLoginFlowAlias  *string           `json:"postBrokerLoginFlowAlias,omitempty"`
	ProviderID                *string           `json:"providerId,omitempty"`
	StoreToken                *bool             `json:"storeToken,omitempty"`
	TrustEmail                *bool             `json:"trustEmail,omitempty"`
	HrdSettings               *HrdSettingModel  `json:"hrdSettings,omitempty"`
}

type HrdSettingModel struct {
	IPRangesList string `json:"ipRangesList"`
	Priority     int    `json:"priority"`
}

// IdentityProviderMapperRepresentation struct
type IdentityProviderMapperRepresentation struct {
	Config                 map[string]string `json:"config,omitempty"`
	ID                     *string           `json:"id,omitempty"`
	IdentityProviderAlias  *string           `json:"identityProviderAlias,omitempty"`
	IdentityProviderMapper *string           `json:"identityProviderMapper,omitempty"`
	Name                   *string           `json:"name,omitempty"`
}

func (settings HrdSettingModel) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp("ipRangesList", &settings.IPRangesList, constants.RegExpIpRangesList, true).
		ValidateParameterIntBetween("priority", &settings.Priority, -100, 0, false).
		Status()
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
		HideOnLogin:               idp.HideOnLogin,
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
		HideOnLogin:               idp.HideOnLogin,
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
	v := validation.NewParameterValidator().
		ValidateParameterRegExp("alias", idp.Alias, constants.RegExpAlias, true).
		ValidateParameterRegExp("displayName", idp.DisplayName, constants.RegExpDisplayName, true).
		ValidateParameterRegExp("firstBrokerLoginFlowAlias", idp.FirstBrokerLoginFlowAlias, constants.RegExpFirstBrokerLoginFlowAlias, true).
		ValidateParameterRegExp("internalId", idp.InternalID, constants.RegExpID, false).
		ValidateParameterRegExp("postBrokerLoginFlowAlias", idp.PostBrokerLoginFlowAlias, constants.RegExpPostBrokerLoginFlowAlias, true).
		ValidateParameterRegExp("providerId", idp.ProviderID, constants.RegExpProviderID, true)

	if len(idp.Config) != 0 {
		configJSON, err := json.Marshal(idp.Config)
		if err != nil {
			return err
		}
		configStr := string(configJSON)
		v = v.ValidateParameterLength("config", &configStr, 0, 10000, false)
	}

	if idp.HrdSettings != nil {
		v = v.ValidateParameterFunc(func() error {
			return idp.HrdSettings.Validate()
		})
	}

	return v.Status()
}

// convertToAPIIdentityProviderMapper creates an API IdentityProviderMapperRepresentation from a KC IdentityProviderMapperRepresentation
func convertToAPIIdentityProviderMapper(kcMapper kc.IdentityProviderMapperRepresentation) IdentityProviderMapperRepresentation {
	return IdentityProviderMapperRepresentation{
		Config:                 kcMapper.Config,
		ID:                     kcMapper.ID,
		IdentityProviderAlias:  kcMapper.IdentityProviderAlias,
		IdentityProviderMapper: kcMapper.IdentityProviderMapper,
		Name:                   kcMapper.Name,
	}
}

// ConvertToAPIIdentityProviderMappers creates API IdentityProviderMapperRepresentations from KC IdentityProviderMapperRepresentations
func ConvertToAPIIdentityProviderMappers(kcMappers []kc.IdentityProviderMapperRepresentation) []IdentityProviderMapperRepresentation {
	apiMappers := make([]IdentityProviderMapperRepresentation, len(kcMappers))
	for i := range kcMappers {
		apiMappers[i] = convertToAPIIdentityProviderMapper(kcMappers[i])
	}

	return apiMappers
}

// ConvertToKCIdentityProviderMapper creates a KC IdentityProviderMapperRepresentation from an API IdentityProviderMapperRepresentation
func ConvertToKCIdentityProviderMapper(apiMapper IdentityProviderMapperRepresentation) kc.IdentityProviderMapperRepresentation {
	return kc.IdentityProviderMapperRepresentation{
		Config:                 apiMapper.Config,
		ID:                     apiMapper.ID,
		IdentityProviderAlias:  apiMapper.IdentityProviderAlias,
		IdentityProviderMapper: apiMapper.IdentityProviderMapper,
		Name:                   apiMapper.Name,
	}
}

// Validate is a validator for IdentityProviderRepresentation
func (mapperRep IdentityProviderMapperRepresentation) Validate() error {
	v := validation.NewParameterValidator().
		ValidateParameterRegExp("id", mapperRep.ID, constants.RegExpID, false).
		ValidateParameterRegExp("identityProviderAlias", mapperRep.IdentityProviderAlias, constants.RegExpAlias, true).
		ValidateParameterRegExp("identityProviderMapper", mapperRep.IdentityProviderMapper, constants.RegExpAlias, true).
		ValidateParameterRegExp("name", mapperRep.Name, constants.RegExpDisplayName, true)

	if len(mapperRep.Config) != 0 {
		configJSON, err := json.Marshal(mapperRep.Config)
		if err != nil {
			return err
		}
		configStr := string(configJSON)
		v = v.ValidateParameterLength("config", &configStr, 0, 10000, false)
	}
	return v.Status()
}
