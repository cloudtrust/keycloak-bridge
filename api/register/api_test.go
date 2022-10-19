package apiregister

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func createValidUser() UserRepresentation {
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
	}
}

func TestJSON(t *testing.T) {
	var user1 = createValidUser()
	var j = user1.UserToJSON()

	var user2, err = UserFromJSON(j)
	assert.Nil(t, err)
	assert.Equal(t, user1, user2)

	_, err = UserFromJSON(`{gender="M",`)
	assert.NotNil(t, err)
	_, err = UserFromJSON(`{gender="M", unknownField=5}`)
	assert.NotNil(t, err)
}

func TestConvertToKeycloak(t *testing.T) {
	var user = createValidUser()
	var kcUser = user.ConvertToKeycloak()

	assert.Equal(t, user.FirstName, kcUser.FirstName)
	assert.Equal(t, user.LastName, kcUser.LastName)
	assert.Equal(t, user.Email, kcUser.Email)
	assert.False(t, *kcUser.EmailVerified)
	assert.True(t, *kcUser.Enabled)
}

func TestValidateUserRepresentation(t *testing.T) {
	var (
		empty          = ""
		invalidDate    = "29.02.2019"
		invalidLocale  = "x789"
		invalidCountry = "xD67x"
	)

	t.Run("Valid users", func(t *testing.T) {
		var user = createValidUser()
		assert.Nil(t, user.Validate(true), "User is expected to be valid")
	})

	t.Run("Invalid users", func(t *testing.T) {
		var users []UserRepresentation
		for i := 0; i < 19; i++ {
			users = append(users, createValidUser())
		}
		// invalid values
		users[0].Gender = &empty
		users[1].FirstName = &empty
		users[2].LastName = &empty
		users[3].Email = &empty
		users[4].PhoneNumber = &empty
		users[5].BirthDate = &invalidDate
		users[6].BirthLocation = &empty
		users[7].Nationality = &empty
		users[8].IDDocumentType = &empty
		users[9].IDDocumentNumber = &empty
		users[10].IDDocumentExpiration = &invalidDate
		users[11].IDDocumentCountry = &invalidCountry
		users[12].Locale = &invalidLocale
		users[13].BusinessID = &empty
		// mandatory parameters
		users[14].FirstName = nil
		users[15].LastName = nil
		users[16].Email = nil
		users[17].PhoneNumber = nil
		users[18].Locale = nil

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(true), "User is expected to be invalid. Test #%d failed with user %s", idx, aUser.UserToJSON())
		}
	})
}
