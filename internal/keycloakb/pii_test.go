package keycloakb

import (
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestConvertLegacyAttribute(t *testing.T) {
	var kcUser kc.UserRepresentation

	t.Run("No attributes", func(t *testing.T) {
		ConvertLegacyAttribute(&kcUser)
		assert.Nil(t, kcUser.Attributes)
	})
	t.Run("One attribute without PII", func(t *testing.T) {
		kcUser.SetAttributeString(kc.AttributeKey("non-pii"), "value")
		ConvertLegacyAttribute(&kcUser)
		assert.Len(t, *kcUser.Attributes, 1)
	})
	t.Run("Two PII attributes in un-encrypted version", func(t *testing.T) {
		var birthDate = "01.01.1999"
		var gender = "M"
		kcUser = kc.UserRepresentation{}
		kcUser.SetAttributeString(attrbBirthDateLegacy, birthDate)
		kcUser.SetAttributeString(attrbGenderLegacy, gender)
		ConvertLegacyAttribute(&kcUser)
		assert.Len(t, *kcUser.Attributes, 2)
		assert.Nil(t, kcUser.GetAttributeString(attrbBirthDateLegacy))
		assert.Nil(t, kcUser.GetAttributeString(attrbGenderLegacy))
		assert.Equal(t, birthDate, *kcUser.GetAttributeString(constants.AttrbBirthDate))
		assert.Equal(t, gender, *kcUser.GetAttributeString(constants.AttrbGender))
	})
}
