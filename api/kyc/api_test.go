package apikyc

import (
	"context"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

func createValidUser() UserRepresentation {
	var (
		bFalse          = false
		username        = "46791834"
		gender          = "M"
		firstName       = "Marc"
		lastName        = "El-Bichoun"
		email           = "marcel.bichon@elca.ch"
		phoneNumber     = "00 33 686 550011"
		birthDate       = "29.02.2020"
		birthLocation   = "Bermuda"
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = "23.02.2039"
		accred1         = AccreditationRepresentation{Type: ptr("short"), ExpiryDate: ptr("31.12.2024")}
		accred2         = AccreditationRepresentation{Type: ptr("long"), ExpiryDate: ptr("31.12.2039")}
		creds           = []AccreditationRepresentation{accred1, accred2}
	)

	return UserRepresentation{
		Username:             &username,
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		Email:                &email,
		EmailVerified:        &bFalse,
		PhoneNumber:          &phoneNumber,
		PhoneNumberVerified:  &bFalse,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
		Accreditations:       &creds,
	}
}

func createValidKeycloakUser() kc.UserRepresentation {
	var (
		bTrue      = true
		firstName  = "Marc"
		lastName   = "El-Bichoun"
		email      = "marcel.bichon@elca.ch"
		attributes = kc.Attributes{
			constants.AttrbGender:              []string{"M"},
			constants.AttrbPhoneNumber:         []string{"00 33 686 550011"},
			constants.AttrbPhoneNumberVerified: []string{"true"},
			constants.AttrbBirthDate:           []string{"29.02.2020"},
			constants.AttrbAccreditations:      []string{`{"type":"one","expiryDate":"05.04.2020"}`, `{"type":"two","expiryDate":"05.03.2022"}`},
		}
	)

	return kc.UserRepresentation{
		Attributes:    &attributes,
		FirstName:     &firstName,
		LastName:      &lastName,
		Email:         &email,
		EmailVerified: &bTrue,
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

func TestExportToKeycloak(t *testing.T) {
	t.Run("Empty user from Keycloak", func(t *testing.T) {
		var user = createValidUser()
		var kcUser = kc.UserRepresentation{}

		user.ExportToKeycloak(&kcUser)

		assert.Equal(t, user.FirstName, kcUser.FirstName)
		assert.Equal(t, user.LastName, kcUser.LastName)
		assert.Equal(t, user.Email, kcUser.Email)
		assert.False(t, *kcUser.EmailVerified)
		assert.True(t, *kcUser.Enabled)
	})

	t.Run("Empty user from API", func(t *testing.T) {
		var user = UserRepresentation{}
		var kcUser = createValidKeycloakUser()

		user.ExportToKeycloak(&kcUser)

		assert.True(t, *kcUser.EmailVerified)
		assert.Equal(t, "true", (*kcUser.Attributes)["phoneNumberVerified"][0])
		assert.True(t, *kcUser.Enabled)
	})

	t.Run("Updates both email and phone", func(t *testing.T) {
		var user = createValidUser()
		var kcUser = createValidKeycloakUser()
		var newEmail = "new-address@cloudtrust.io"
		var newPhoneNumber = "00 41 22 345 45 78"
		var verified = true
		user.Email = &newEmail
		user.PhoneNumber = &newPhoneNumber
		// Verified flags from api.UserRepresentation must be ignored
		user.EmailVerified = &verified
		user.PhoneNumberVerified = &verified

		user.ExportToKeycloak(&kcUser)

		assert.Equal(t, user.FirstName, kcUser.FirstName)
		assert.Equal(t, user.LastName, kcUser.LastName)
		assert.Equal(t, user.Email, kcUser.Email)
		assert.Equal(t, *user.PhoneNumber, *kcUser.GetAttributeString(constants.AttrbPhoneNumber))
		assert.False(t, *kcUser.EmailVerified)
		assert.Equal(t, "false", *kcUser.GetAttributeString(constants.AttrbPhoneNumberVerified))
		assert.True(t, *kcUser.Enabled)
	})
}

func TestImportFromKeycloak(t *testing.T) {
	var ctx = context.TODO()
	var logger = log.NewNopLogger()

	var kcUser = createValidKeycloakUser()
	kcUser.SetAttributeBool(constants.AttrbPhoneNumberVerified, true)

	// Add an invalid JSON accreditation: it will be ignored
	var accreds = append(kcUser.Attributes.Get(constants.AttrbAccreditations), "{")
	kcUser.Attributes.Set(constants.AttrbAccreditations, accreds)
	assert.Equal(t, 3, len(kcUser.Attributes.Get(constants.AttrbAccreditations)))

	var imported = UserRepresentation{}
	imported.ImportFromKeycloak(ctx, &kcUser, logger)

	assert.Equal(t, *kcUser.FirstName, *imported.FirstName)
	assert.Equal(t, *kcUser.LastName, *imported.LastName)
	assert.Equal(t, *kcUser.GetAttributeString(constants.AttrbGender), *imported.Gender)
	assert.Len(t, *imported.Accreditations, 2)
	assert.True(t, *imported.PhoneNumberVerified)
}

func TestValidateUserRepresentation(t *testing.T) {
	var (
		empty       = ""
		user        = createValidUser()
		invalidDate = "29.02.2019"
	)

	t.Run("Valid users", func(t *testing.T) {
		assert.Nil(t, user.Validate(), "User is expected to be valid")
	})

	t.Run("Invalid users", func(t *testing.T) {
		var users []UserRepresentation
		for i := 0; i < 20; i++ {
			users = append(users, user)
		}
		// invalid values
		users[0].Gender = &empty
		users[1].FirstName = &empty
		users[2].LastName = &empty
		users[3].Email = &empty
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
		users[13].Email = nil
		users[14].PhoneNumber = nil
		users[15].BirthDate = nil
		users[16].BirthLocation = nil
		users[17].IDDocumentType = nil
		users[18].IDDocumentNumber = nil
		users[19].IDDocumentExpiration = nil

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid. Test #%d failed with user %s", idx, aUser.UserToJSON())
		}
	})
}
