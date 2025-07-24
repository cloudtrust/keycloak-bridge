package apiregister

import (
	"strings"
	"testing"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func createValidUser(customAttribute string) UserRepresentation {
	var (
		gender          = "M"
		firstName       = "Marc"
		lastName        = "El-Bichoun"
		email           = "marcel.bichon@elca.ch"
		phoneNumber     = "00 33 686 550011"
		birthDate       = "29.02.2020"
		birthLocation   = "St. Gallen"
		nationality     = "DE"
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = "23.02.2039"
		idDocCountry    = "FR"
		locale          = "de"
		customValue     = "customValue"
	)

	return UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		Email:                &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		Nationality:          &nationality,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
		IDDocumentCountry:    &idDocCountry,
		Locale:               &locale,
		Dynamic:              map[string]any{customAttribute: customValue},
	}
}

func TestConvertToKeycloak(t *testing.T) {
	customAttribute := "customAttribute"
	profile := kc.UserProfileRepresentation{
		Attributes: []kc.ProfileAttrbRepresentation{
			{
				Name:        &customAttribute,
				Annotations: map[string]string{"dynamic": "true"},
			},
		},
	}
	profile.InitDynamicAttributes()
	var user = createValidUser(customAttribute)
	var kcUser = user.ConvertToKeycloak(profile)

	assert.Equal(t, user.FirstName, kcUser.FirstName)
	assert.Equal(t, user.LastName, kcUser.LastName)
	assert.Equal(t, user.Email, kcUser.Email)
	assert.False(t, *kcUser.EmailVerified)
	assert.True(t, *kcUser.Enabled)
	assert.Equal(t, user.Dynamic[customAttribute], kcUser.GetDynamicAttributes(profile)[customAttribute])
}

func TestGetSetUserField(t *testing.T) {
	for _, field := range []string{
		"username:12345678", "email:name@domain.ch", "firstName:firstname", "lastName:lastname", "ENC_gender:M", "phoneNumber:+41223145789",
		"ENC_birthDate:12.11.2010", "ENC_birthLocation:chezouam", "ENC_nationality:ch", "ENC_idDocumentType:PASSPORT", "ENC_idDocumentNumber:123-456-789",
		"ENC_idDocumentExpiration:01.01.2039", "ENC_idDocumentCountry:ch", "locale:fr", "businessID:456789",
	} {
		var parts = strings.Split(field, ":")
		testGetSetUserField(t, parts[0], parts[1])
	}
	var user = UserRepresentation{}
	assert.Nil(t, user.GetField("not-existing-field"))
}

func testGetSetUserField(t *testing.T, fieldName string, value interface{}) {
	var user UserRepresentation
	t.Run("Field "+fieldName, func(t *testing.T) {
		assert.Nil(t, user.GetField(fieldName))
		user.SetField(fieldName, value)
		assert.Equal(t, value, *user.GetField(fieldName).(*string))
	})
}
