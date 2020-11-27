package dto

import (
	"encoding/json"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client"
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

func TestSetDetails(t *testing.T) {
	var dbUser = DBUser{
		BirthLocation:        ptr("Lausanne"),
		Nationality:          ptr("CH"),
		IDDocumentType:       ptr("PASSPORT"),
		IDDocumentNumber:     ptr("1234567890123"),
		IDDocumentExpiration: ptr("10.01.2030"),
		IDDocumentCountry:    ptr("CH"),
	}
	var user ArchiveUserRepresentation

	user.SetDetails(dbUser)
	assert.Equal(t, dbUser.BirthLocation, user.BirthLocation)
	assert.Equal(t, dbUser.Nationality, user.Nationality)
	assert.Equal(t, dbUser.IDDocumentType, user.IDDocumentType)
	assert.Equal(t, dbUser.IDDocumentNumber, user.IDDocumentNumber)
	assert.Equal(t, dbUser.IDDocumentExpiration, user.IDDocumentExpiration)
	assert.Equal(t, dbUser.IDDocumentCountry, user.IDDocumentCountry)
}
