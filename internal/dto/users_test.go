package dto

import (
	"testing"

	"github.com/cloudtrust/common-service/v2/fields"
	"github.com/stretchr/testify/assert"
)

func TestGetFieldValues(t *testing.T) {
	var user = DBUser{
		BirthLocation:        ptr("Lausanne"),
		Nationality:          ptr("DE"),
		IDDocumentType:       ptr("Driving licence"),
		IDDocumentNumber:     ptr("1234567890"),
		IDDocumentExpiration: ptr("31.12.2039"),
		IDDocumentCountry:    ptr("CH"),
	}
	var emptyUser = DBUser{}
	assert.Nil(t, user.GetFieldValues(fields.FirstName))
	assert.Nil(t, emptyUser.GetFieldValues(fields.BirthLocation))
	assert.Equal(t, *user.BirthLocation, user.GetFieldValues(fields.BirthLocation)[0])
	assert.Equal(t, *user.Nationality, user.GetFieldValues(fields.Nationality)[0])
	assert.Equal(t, *user.IDDocumentType, user.GetFieldValues(fields.IDDocumentType)[0])
	assert.Equal(t, *user.IDDocumentNumber, user.GetFieldValues(fields.IDDocumentNumber)[0])
	assert.Equal(t, *user.IDDocumentExpiration, user.GetFieldValues(fields.IDDocumentExpiration)[0])
	assert.Equal(t, *user.IDDocumentCountry, user.GetFieldValues(fields.IDDocumentCountry)[0])
}
