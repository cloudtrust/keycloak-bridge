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

// HrdSettingModel struct
type HrdSettingModel struct {
	IPRangesList *string `json:"ipRangesList,omitempty"`
	DomainsList  *string `json:"domainsList,omitempty"`
	Priority     int     `json:"priority"`
}

// IdentityProviderMapperRepresentation struct
type IdentityProviderMapperRepresentation struct {
	Config                 map[string]string `json:"config,omitempty"`
	ID                     *string           `json:"id,omitempty"`
	IdentityProviderAlias  *string           `json:"identityProviderAlias,omitempty"`
	IdentityProviderMapper *string           `json:"identityProviderMapper,omitempty"`
	Name                   *string           `json:"name,omitempty"`
}

// UserRepresentation struct
type UserRepresentation struct {
	ID         *string  `json:"id,omitempty"`
	Username   *string  `json:"username,omitempty"`
	FirstName  *string  `json:"firstName,omitempty"`
	LastName   *string  `json:"lastName,omitempty"`
	Email      *string  `json:"email,omitempty"`
	Enabled    *bool    `json:"enabled,omitempty"`
	RealmRoles []string `json:"roles,omitempty"`
}

// FederatedIdentityRepresentation struct
type FederatedIdentityRepresentation struct {
	UserID           *string `json:"userID,omitempty"`
	Username         *string `json:"username,omitempty"`
	IdentityProvider *string `json:"identityProvider,omitempty"`
}

func validateConfig(config map[string]string) func() error {
	return func() error {
		if len(config) != 0 {
			configJSON, err := json.Marshal(config)
			if err != nil {
				return err
			}
			configStr := string(configJSON)
			return validation.NewParameterValidator().ValidateParameterLength("config", &configStr, 0, 10000, false).Status()
		}
		return nil
	}
}

// Validate validates a HrdSettingModel
func (settings HrdSettingModel) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp("ipRangesList", settings.IPRangesList, constants.RegExpIpRangesList, false).
		ValidateParameterRegExp("domainsList", settings.DomainsList, constants.RegExpDomainsList, false).
		ValidateParameterIntBetween("priority", &settings.Priority, -1000, 1000, true).
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
func (idp IdentityProviderRepresentation) ConvertToKCIdentityProvider() kc.IdentityProviderRepresentation {
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
	return validation.NewParameterValidator().
		ValidateParameterRegExp("alias", idp.Alias, constants.RegExpAlias, true).
		ValidateParameterRegExp("displayName", idp.DisplayName, constants.RegExpIdpDisplayName, true).
		ValidateParameterRegExp("firstBrokerLoginFlowAlias", idp.FirstBrokerLoginFlowAlias, constants.RegExpFirstBrokerLoginFlowAlias, true).
		ValidateParameterRegExp("internalId", idp.InternalID, constants.RegExpID, false).
		ValidateParameterRegExp("postBrokerLoginFlowAlias", idp.PostBrokerLoginFlowAlias, constants.RegExpPostBrokerLoginFlowAlias, true).
		ValidateParameterRegExp("providerId", idp.ProviderID, constants.RegExpProviderID, true).
		ValidateParameterFunc(validateConfig(idp.Config)).
		ValidateParameter("hrdSettings", idp.HrdSettings, false).
		Status()
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
func (mapperRep IdentityProviderMapperRepresentation) ConvertToKCIdentityProviderMapper() kc.IdentityProviderMapperRepresentation {
	return kc.IdentityProviderMapperRepresentation{
		Config:                 mapperRep.Config,
		ID:                     mapperRep.ID,
		IdentityProviderAlias:  mapperRep.IdentityProviderAlias,
		IdentityProviderMapper: mapperRep.IdentityProviderMapper,
		Name:                   mapperRep.Name,
	}
}

// Validate is a validator for IdentityProviderRepresentation
func (mapperRep IdentityProviderMapperRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp("id", mapperRep.ID, constants.RegExpID, false).
		ValidateParameterRegExp("identityProviderAlias", mapperRep.IdentityProviderAlias, constants.RegExpAlias, true).
		ValidateParameterRegExp("identityProviderMapper", mapperRep.IdentityProviderMapper, constants.RegExpAlias, true).
		ValidateParameterRegExp("name", mapperRep.Name, constants.RegExpDisplayName, true).
		ValidateParameterFunc(validateConfig(mapperRep.Config)).
		Status()
}

// ConvertToAPIUserRepresentations converts a slice of KC user representation to a slice of API UserRepresentation
func ConvertToAPIUserRepresentations(kcUsers []kc.UserRepresentation) []UserRepresentation {
	var res []UserRepresentation
	for _, user := range kcUsers {
		res = append(res, ConvertToAPIUserRepresentation(user))
	}
	return res
}

// ConvertToAPIUserRepresentation converts a KC user representation to an API UserRepresentation
func ConvertToAPIUserRepresentation(kcUser kc.UserRepresentation) UserRepresentation {
	var realmRoles []string
	if kcUser.RealmRoles != nil && len(*kcUser.RealmRoles) > 0 {
		realmRoles = *kcUser.RealmRoles
	}
	return UserRepresentation{
		ID:         kcUser.ID,
		Username:   kcUser.Username,
		FirstName:  kcUser.FirstName,
		LastName:   kcUser.LastName,
		Email:      kcUser.Email,
		Enabled:    kcUser.Enabled,
		RealmRoles: realmRoles,
	}
}

// ConvertToKCUserRepresentation converts an API UserRepresentation to a KC UserRepresentation
func (u UserRepresentation) ConvertToKCUserRepresentation() kc.UserRepresentation {
	var realmRoles *[]string
	if len(u.RealmRoles) > 0 {
		realmRoles = &u.RealmRoles
	}
	return kc.UserRepresentation{
		ID:         u.ID,
		Username:   u.Username,
		FirstName:  u.FirstName,
		LastName:   u.LastName,
		Email:      u.Email,
		Enabled:    u.Enabled,
		RealmRoles: realmRoles,
	}
}
