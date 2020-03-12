package validation

import (
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func createValidUser() UserRepresentation {
	var (
		bFalse          = false
		username        = "46791834"
		gender          = "M"
		firstName       = "Marc"
		lastName        = "El-Bichoun"
		email           = "marcel.bichon@elca.ch"
		phoneNumber     = "00 33 686 550011"
		birthDate       = time.Now()
		birthLocation   = "Bermuda"
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = time.Now()
	)

	return UserRepresentation{
		Username:             &username,
		Gender:               &gender,
		FirstName:            &firstName,
		LastName:             &lastName,
		EmailAddress:         &email,
		EmailAddressVerified: &bFalse,
		PhoneNumber:          &phoneNumber,
		PhoneNumberVerified:  &bFalse,
		BirthDate:            &birthDate,
		BirthLocation:        &birthLocation,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
	}
}

func createValidKeycloakUser() kc.UserRepresentation {
	var (
		bTrue      = true
		firstName  = "Marc"
		lastName   = "El-Bichoun"
		email      = "marcel.bichon@elca.ch"
		attributes = kc.Attributes{
			"gender":              []string{"M"},
			"phoneNumber":         []string{"00 33 686 550011"},
			"phoneNumberVerified": []string{"true"},
			"birthDate":           []string{"29.02.2020"},
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

func createValidCheck() CheckRepresentation {
	var (
		userID    = "12345678-5824-5555-5656-123456789654"
		operator  = "operator"
		datetime  = time.Now()
		status    = "SUCCESS"
		typeCheck = "IDENTITY_CHECK"
		nature    = "PHYSICAL"
		proofType = "ZIP"
		proofData = []byte("data")
	)

	return CheckRepresentation{
		UserID:    &userID,
		Operator:  &operator,
		DateTime:  &datetime,
		Status:    &status,
		Type:      &typeCheck,
		Nature:    &nature,
		ProofType: &proofType,
		ProofData: &proofData,
	}
}

func TestExportToKeycloak(t *testing.T) {
	t.Run("Empty user from Keycloak", func(t *testing.T) {
		var user = createValidUser()
		var kcUser = kc.UserRepresentation{}

		user.ExportToKeycloak(&kcUser)

		assert.Equal(t, user.FirstName, kcUser.FirstName)
		assert.Equal(t, user.LastName, kcUser.LastName)
		assert.Equal(t, user.EmailAddress, kcUser.Email)
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
		var newEmailAddress = "new-address@cloudtrust.io"
		var newPhoneNumber = "00 41 22 345 45 78"
		var verified = true
		user.EmailAddress = &newEmailAddress
		user.PhoneNumber = &newPhoneNumber
		// Verified flags from api.UserRepresentation must be ignored
		user.EmailAddressVerified = &verified
		user.PhoneNumberVerified = &verified

		user.ExportToKeycloak(&kcUser)

		assert.Equal(t, user.FirstName, kcUser.FirstName)
		assert.Equal(t, user.LastName, kcUser.LastName)
		assert.Equal(t, user.EmailAddress, kcUser.Email)
		assert.Equal(t, *user.PhoneNumber, (*kcUser.Attributes)["phoneNumber"][0])
		assert.False(t, *kcUser.EmailVerified)
		assert.Equal(t, "false", (*kcUser.Attributes)["phoneNumberVerified"][0])
		assert.True(t, *kcUser.Enabled)
	})
}

func TestImportFromKeycloak(t *testing.T) {
	var dateLayout = constants.SupportedDateLayouts[0]
	var user = createValidUser()
	user.BirthLocation = nil
	user.IDDocumentType = nil
	user.IDDocumentNumber = nil
	user.IDDocumentExpiration = nil

	var kcUser kc.UserRepresentation
	user.ExportToKeycloak(&kcUser)

	var imported = UserRepresentation{}
	imported.ImportFromKeycloak(kcUser)

	assert.Equal(t, (*user.BirthDate).Format(dateLayout), (*imported.BirthDate).Format(dateLayout))

	user.BirthDate = nil
	imported.BirthDate = nil
	assert.Equal(t, user, imported)
}

func TestUserValidate(t *testing.T) {
	var (
		invalid = ""
		user    = createValidUser()
	)

	t.Run("Valid users", func(t *testing.T) {
		assert.Nil(t, user.Validate(), "User is expected to be valid")
	})

	t.Run("Invalid users", func(t *testing.T) {
		var users = []UserRepresentation{user, user, user, user, user, user, user, user}
		// invalid values
		users[0].Gender = &invalid
		users[1].FirstName = &invalid
		users[2].LastName = &invalid
		users[3].EmailAddress = &invalid
		users[4].PhoneNumber = &invalid
		users[5].BirthLocation = &invalid
		users[6].IDDocumentType = &invalid
		users[7].IDDocumentNumber = &invalid

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid. Test #%d failed", idx)
		}
	})
}

func TestCheckValidate(t *testing.T) {
	var (
		invalid = ""
		check   = createValidCheck()
	)

	t.Run("Valid checks", func(t *testing.T) {
		assert.Nil(t, check.Validate(), "Check is expected to be valid")
	})

	t.Run("Invalid checks", func(t *testing.T) {
		var checks = []CheckRepresentation{check, check, check, check, check, check, check, check, check, check, check}
		// invalid values
		checks[0].Operator = &invalid
		checks[1].Status = &invalid
		checks[2].Type = &invalid
		checks[3].Nature = &invalid
		checks[4].ProofType = &invalid
		// mandatory parameters
		checks[5].Operator = nil
		checks[6].DateTime = nil
		checks[7].Status = nil
		checks[8].Type = nil
		checks[9].Nature = nil
		checks[10].ProofType = nil

		for idx, aCheck := range checks {
			assert.NotNil(t, aCheck.Validate(), "Check is expected to be invalid. Test #%d failed", idx)
		}
	})
}

func TestIsIdentificationSuccessful(t *testing.T) {
	var check CheckRepresentation
	t.Run("Status is nil", func(t *testing.T) {
		check.Status = nil
		assert.False(t, check.IsIdentificationSuccessful())
	})
	t.Run("Status is not a known success value", func(t *testing.T) {
		var unknown = "unknown"
		check.Status = &unknown
		assert.False(t, check.IsIdentificationSuccessful())
	})
	t.Run("Status is a success value", func(t *testing.T) {
		var success = "SUCCESS"
		check.Status = &success
		assert.True(t, check.IsIdentificationSuccessful())
	})
}
