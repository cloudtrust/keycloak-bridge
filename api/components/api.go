package apicomponent

import (
	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

// ComponentRepresentation struct
type ComponentRepresentation struct {
	Config       *map[string][]string `json:"config,omitempty"`
	ID           *string              `json:"id,omitempty"`
	Name         *string              `json:"name,omitempty"`
	ParentID     *string              `json:"parentId,omitempty"`
	ProviderID   *string              `json:"providerId,omitempty"`
	ProviderType *string              `json:"providerType,omitempty"`
	SubType      *string              `json:"subType,omitempty"`
}

// ConvertToAPIComponent creates an API ComponentRepresentation from a KC ComponentRepresentation
func ConvertToAPIComponent(component kc.ComponentRepresentation) ComponentRepresentation {
	return ComponentRepresentation{
		Config:       component.Config,
		ID:           component.ID,
		Name:         component.Name,
		ParentID:     component.ParentID,
		ProviderID:   component.ProviderID,
		ProviderType: component.ProviderType,
		SubType:      component.SubType,
	}
}

// ConvertToKCComponent creates a KC ComponentRepresentation from an API ComponentRepresentation
func ConvertToKCComponent(component ComponentRepresentation) kc.ComponentRepresentation {
	return kc.ComponentRepresentation{
		Config:       component.Config,
		ID:           component.ID,
		Name:         component.Name,
		ParentID:     component.ParentID,
		ProviderID:   component.ProviderID,
		ProviderType: component.ProviderType,
		SubType:      component.SubType,
	}
}

// Validate is a validator for ComponentRepresentation
func (component ComponentRepresentation) Validate() error {
	return validation.NewParameterValidator().
		ValidateParameterRegExp("id", component.ID, constants.RegExpComponentID, true).
		ValidateParameterRegExp("name", component.Name, constants.RegExpComponentName, false).
		ValidateParameterRegExp("parentId", component.ParentID, constants.RegExpComponentParentID, false).
		ValidateParameterRegExp("providerId", component.ProviderID, constants.RegExpComponentProviderID, true).
		ValidateParameterRegExp("providerType", component.ProviderType, constants.RegExpComponentProviderType, true).
		ValidateParameterRegExp("subType", component.SubType, constants.RegExpComponentSubType, false).
		Status()
}
