package apicommon

import (
	"strings"

	"github.com/cloudtrust/common-service/v2/validation"
	"github.com/cloudtrust/keycloak-bridge/internal/profile"
	kc "github.com/cloudtrust/keycloak-client/v2"
)

const (
	requesterType = "user"
)

var allowAnnotation = map[string]bool{
	"values":     true,
	"account":    false,
	"kyc":        false,
	"management": false,
	"register":   false,
}

// ProfileRepresentation representation
type ProfileRepresentation struct {
	Attributes []ProfileAttributeRepresentation `json:"attributes,omitempty"`
	Groups     []ProfileGroupRepresentation     `json:"groups,omitempty"`
}

// ProfileAttributeRepresentation struct
type ProfileAttributeRepresentation struct {
	Name        *string                                        `json:"name,omitempty"`
	DisplayName *string                                        `json:"displayName,omitempty"`
	Group       *string                                        `json:"group,omitempty"`
	Required    *bool                                          `json:"required,omitempty"`
	Validations map[string]ProfileAttrbValidatorRepresentation `json:"validations,omitempty"`
	Annotations map[string]string                              `json:"annotations,omitempty"`
}

// ProfileAttrbValidatorRepresentation type
type ProfileAttrbValidatorRepresentation map[string]interface{}

// ProfileGroupRepresentation struct
type ProfileGroupRepresentation struct {
	Name               *string           `json:"name,omitempty"`
	DisplayHeader      *string           `json:"displayHeader,omitempty"`
	DisplayDescription *string           `json:"displayDescription,omitempty"`
	Annotations        map[string]string `json:"annotations,omitempty"`
}

// ProfileToApi converts a KC UserProfile to its API version
func ProfileToApi(profile kc.UserProfileRepresentation, frontend string) ProfileRepresentation {
	return ProfileRepresentation{
		Attributes: AttributesToApi(profile.Attributes, frontend),
		Groups:     GroupsToApi(profile.Groups),
	}
}

// AttributesToApi converts a KC profile attribute to its API version
func AttributesToApi(attrbs []kc.ProfileAttrbRepresentation, frontend string) []ProfileAttributeRepresentation {
	if attrbs == nil {
		return nil
	}
	var res = []ProfileAttributeRepresentation{}
	for _, attrb := range attrbs {
		var newValue = AttributeToApi(attrb, frontend)
		if newValue != nil {
			res = append(res, *newValue)
		}
	}
	return res
}

func AttributeToApi(attrb kc.ProfileAttrbRepresentation, apiName string) *ProfileAttributeRepresentation {
	if attrb.Permissions != nil && !validation.IsStringInSlice(attrb.Permissions.Edit, requesterType) {
		// User has no permission to edit this field
		// Component should not be aware of its existence
		return nil
	}
	// By default, attributes are not shown for a given frontend
	if apiName != "" && (!attrb.AnnotationMatches(apiName, func(value string) bool {
		return strings.EqualFold(value, "true") || strings.EqualFold(value, "required")
	})) {
		// Attribute is not declared to be used by the given frontend
		return nil
	}
	var required = profile.IsAttributeRequired(attrb, apiName)
	return &ProfileAttributeRepresentation{
		Name:        cleanUpName(attrb.Name),
		DisplayName: attrb.DisplayName,
		Group:       attrb.Group,
		Required:    &required,
		Validations: ValidationsToApi(attrb.Validations),
		Annotations: AttributeAnnotationsToApi(attrb.Annotations),
	}
}

func cleanUpName(name *string) *string {
	if name == nil {
		return nil
	}
	var res = strings.ReplaceAll(*name, "ENC_", "")
	return &res
}

// ValidationsToApi converts KC validators
func ValidationsToApi(validations kc.ProfileAttrbValidationRepresentation) map[string]ProfileAttrbValidatorRepresentation {
	if validations == nil {
		return nil
	}
	var res = make(map[string]ProfileAttrbValidatorRepresentation)
	for k, v := range validations {
		res[k] = ToValidator(v)
	}

	return res
}

// ToValidator converts a KC validator
func ToValidator(validator kc.ProfileAttrValidatorRepresentation) ProfileAttrbValidatorRepresentation {
	if validator == nil {
		return nil
	}
	var res = make(ProfileAttrbValidatorRepresentation)
	for k, v := range validator {
		res[k] = v
	}
	return res
}

// AttributeAnnotationsToApi converts a KC attribute annotations
func AttributeAnnotationsToApi(annotations map[string]string) map[string]string {
	var res = make(map[string]string)
	if annotations != nil {
		for key, value := range annotations {
			if allow, ok := allowAnnotation[key]; ok && allow {
				res[key] = value
			}
		}
	}
	return res
}

// GroupsToApi converts KC users profile groups to its API version
func GroupsToApi(groups []kc.ProfileGroupRepresentation) []ProfileGroupRepresentation {
	if groups == nil {
		return nil
	}
	var res = []ProfileGroupRepresentation{}
	for _, group := range groups {
		res = append(res, ProfileGroupRepresentation{
			Name:               group.Name,
			DisplayHeader:      group.DisplayHeader,
			DisplayDescription: group.DisplayDescription,
			Annotations:        group.Annotations,
		})
	}
	return res
}
