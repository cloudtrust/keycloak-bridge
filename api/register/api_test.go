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
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = "23.02.2039"
		locale          = "de"
	)

	return UserRepresentation{
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		EmailAddress:         &email,
		PhoneNumber:          &phoneNumber,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
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
	assert.Equal(t, user.EmailAddress, kcUser.Email)
	assert.False(t, *kcUser.EmailVerified)
	assert.True(t, *kcUser.Enabled)
}

func TestValidateUserRepresentation(t *testing.T) {
	var (
		empty         = ""
		user          = createValidUser()
		invalidDate   = "29.02.2019"
		invalidLocale = "x789"
	)

	t.Run("Valid users", func(t *testing.T) {
		assert.Nil(t, user.Validate(), "User is expected to be valid")
	})

	t.Run("Invalid users", func(t *testing.T) {
		var users []UserRepresentation
		for i := 0; i < 22; i++ {
			users = append(users, user)
		}
		// invalid values
		users[0].Gender = &empty
		users[1].FirstName = &empty
		users[2].LastName = &empty
		users[3].EmailAddress = &empty
		users[4].PhoneNumber = &empty
		users[5].BirthDate = &invalidDate
		users[6].BirthLocation = &empty
		users[7].IDDocumentType = &empty
		users[8].IDDocumentNumber = &empty
		users[9].IDDocumentExpiration = &invalidDate
		users[10].Locale = &invalidLocale
		// mandatory parameters
		users[11].Gender = nil
		users[12].FirstName = nil
		users[13].LastName = nil
		users[14].EmailAddress = nil
		users[15].PhoneNumber = nil
		users[16].BirthDate = nil
		users[17].BirthLocation = nil
		users[18].IDDocumentType = nil
		users[19].IDDocumentNumber = nil
		users[20].IDDocumentExpiration = nil
		users[21].Locale = nil

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid. Test #%d failed with user %s", idx, aUser.UserToJSON())
		}
	})
}
