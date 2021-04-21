package keycloakb

import (
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	kc "github.com/cloudtrust/keycloak-client"
)

var (
	// These attributes should not be used anymore
	attrbBirthDateLegacy = kc.AttributeKey("birthDate")
	attrbGenderLegacy    = kc.AttributeKey("gender")

	piiAttributes = map[kc.AttributeKey]kc.AttributeKey{
		constants.AttrbBirthDate: attrbBirthDateLegacy,
		constants.AttrbGender:    attrbGenderLegacy,
	}
)

// ConvertLegacyAttribute ensure that PII are located in the well named attributes
func ConvertLegacyAttribute(user *kc.UserRepresentation) {
	for attrbSecure, attrbLegacy := range piiAttributes {
		if value := user.GetAttributeString(attrbSecure); value == nil {
			if value = user.GetAttributeString(attrbLegacy); value != nil {
				user.SetAttributeString(attrbSecure, *value)
				delete(*user.Attributes, attrbLegacy)
			}
		}
	}
}
