package dto

import (
	"encoding/json"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

func TestToArchiveUserRepresentation(t *testing.T) {
	var attrbs = make(kc.Attributes)
	var bFalse = false
	var kcUser = kc.UserRepresentation{
		ID:         ptr("user-id"),
		Attributes: &attrbs,
	}
	var accred = ArchiveAccreditationRepresentation{
		Type:       ptr("DEP"),
		ExpiryDate: ptr("20.02.2029"),
		Revoked:    &bFalse,
	}
	var accredBytes, _ = json.Marshal(accred)
	var accredJSON = string(accredBytes)

	t.Run("No accreditations", func(t *testing.T) {
		var user = ToArchiveUserRepresentation(kcUser)
		assert.Equal(t, kcUser.ID, user.ID)
		assert.Len(t, user.Accreditations, 0)
	})

	t.Run("With accreditations", func(t *testing.T) {
		kcUser.Attributes.SetString(constants.AttrbAccreditations, accredJSON)
		var user = ToArchiveUserRepresentation(kcUser)
		assert.Len(t, user.Accreditations, 1)
	})
}
