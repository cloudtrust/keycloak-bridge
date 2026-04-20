package dto

import (
	"encoding/json"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func TestToArchiveUserRepresentation(t *testing.T) {
	var attrbs = make(kc.Attributes)
	var bFalse = false
	var kcUser = kc.UserRepresentation{
		ID:         new("user-id"),
		Attributes: &attrbs,
	}
	var accred = ArchiveAccreditationRepresentation{
		Type:       new("DEP"),
		ExpiryDate: new("20.02.2029"),
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
