package apiregister

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func createValidUser() User {
	var (
		gender          = "M"
		firstName       = "Marc"
		lastName        = "El-Bichoun"
		email           = "marcel.bichon@elca.ch"
		phoneNumber     = "00 33 686 550011"
		birthDate       = "29.02.2020"
		birthLocation   = "Bermuda"
		idDocType       = "Passport"
		idDocNumber     = "123456789"
		idDocExpiration = "23.02.2039"
	)

	return User{
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

func TestToKeycloakUser(t *testing.T) {
	var user = createValidUser()
	var kcUser = kc.UserRepresentation{}

	user.UpdateUserRepresentation(&kcUser)

	assert.Equal(t, user.FirstName, kcUser.FirstName)
	assert.Equal(t, user.LastName, kcUser.LastName)
	assert.Equal(t, user.EmailAddress, kcUser.Email)
	assert.False(t, *kcUser.EmailVerified)
	assert.False(t, *kcUser.Enabled)
}

func TestValidateParameterIn(t *testing.T) {
	var (
		empty       = ""
		user        = createValidUser()
		invalidDate = "29.02.2019"
	)

	t.Run("Valid users", func(t *testing.T) {
		var users = []User{user, user, user, user, user, user}
		users[1].BirthDate = nil
		users[2].BirthLocation = nil
		users[3].IDDocumentType = nil
		users[4].IDDocumentNumber = nil
		users[5].IDDocumentExpiration = nil
		for idx, aUser := range users {
			assert.Nil(t, aUser.Validate(), "User is expected to be valid. Test #%d failed with user %s", idx, aUser.UserToJSON())
		}
	})

	t.Run("Invalid users", func(t *testing.T) {
		var users = []User{user, user, user, user, user, user, user, user, user, user, user, user, user, user, user}
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
		// mandatory parameters
		users[10].Gender = nil
		users[11].FirstName = nil
		users[12].LastName = nil
		users[13].EmailAddress = nil
		users[14].PhoneNumber = nil

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid. Test #%d failed with user %s", idx, aUser.UserToJSON())
		}
	})
}

func TestValidateParameterDate(t *testing.T) {
	var invalidDate = "29.02.2019"
	var validDate = "29.02.2020"

	assert.NotNil(t, validateParameterDate("date", nil, true))
	assert.Nil(t, validateParameterDate("date", nil, false))

	assert.NotNil(t, validateParameterDate("date", &invalidDate, true))
	assert.Nil(t, validateParameterDate("date", &validDate, true))
}
