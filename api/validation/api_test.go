package apivalidation

import (
	"fmt"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

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
		nationality     = "DE"
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = time.Now()
		idDocCountry    = "CH"
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
		Nationality:          &nationality,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
		IDDocumentCountry:    &idDocCountry,
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

func createValidPendingChecks() PendingChecksRepresentation {
	var (
		nature = "PHYSICAL"
	)

	return PendingChecksRepresentation{
		Nature: &nature,
	}
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
	var dateLayout = constants.SupportedDateLayouts[0]
	var user = createValidUser()
	user.BirthLocation = nil
	user.Nationality = nil
	user.IDDocumentType = nil
	user.IDDocumentNumber = nil
	user.IDDocumentExpiration = nil
	user.IDDocumentCountry = nil

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
		var users []UserRepresentation
		for i := 0; i < 10; i++ {
			users = append(users, createValidUser())
		}
		// invalid values
		users[0].Gender = &invalid
		users[1].FirstName = &invalid
		users[2].LastName = &invalid
		users[3].Email = &invalid
		users[4].PhoneNumber = &invalid
		users[5].BirthLocation = &invalid
		users[6].Nationality = &invalid
		users[7].IDDocumentType = &invalid
		users[8].IDDocumentNumber = &invalid
		users[9].IDDocumentCountry = &invalid

		for idx, aUser := range users {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid. Test #%d failed", idx)
		}
	})
}

func ptr(v string) *string {
	return &v
}

func TestHasUpdateOfAccreditationDependantInformationDB(t *testing.T) {
	var user UserRepresentation
	var dbUser dto.DBUser

	t.Run("Nothing to update", func(t *testing.T) {
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Expiry date update", func(t *testing.T) {
		var expiryTxt = "15.06.2018"
		var expiry, _ = time.Parse(constants.SupportedDateLayouts[0], "29.12.2019")
		user.IDDocumentExpiration = &expiry
		dbUser.IDDocumentExpiration = &expiryTxt
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		expiry, _ = time.Parse(constants.SupportedDateLayouts[0], expiryTxt)
		user.IDDocumentExpiration = &expiry
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Nationality", func(t *testing.T) {
		var nationality = "TYPE1"
		user.Nationality = ptr("OTHER-NATIONALITY")
		dbUser.Nationality = &nationality
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		user.Nationality = &nationality
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Document type update", func(t *testing.T) {
		var documentType = "TYPE1"
		user.IDDocumentType = ptr("OTHER-TYPE")
		dbUser.IDDocumentType = &documentType
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		user.IDDocumentType = &documentType
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Document number update", func(t *testing.T) {
		var documentNumber = "1234567890"
		user.IDDocumentNumber = ptr("OTHER-NUMBER")
		dbUser.IDDocumentNumber = &documentNumber
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		user.IDDocumentNumber = &documentNumber
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Document country update", func(t *testing.T) {
		var documentCountry = "DE"
		user.IDDocumentCountry = ptr("CH")
		dbUser.IDDocumentCountry = &documentCountry
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		user.IDDocumentCountry = &documentCountry
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
	t.Run("Birth location update", func(t *testing.T) {
		var birthLocation = "Where"
		user.BirthLocation = ptr("Here !")
		dbUser.BirthLocation = &birthLocation
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))

		user.BirthLocation = &birthLocation
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationDB(dbUser))
	})
}

func TestHasUpdateOfAccreditationDependantInformationKC(t *testing.T) {
	var user UserRepresentation
	var kcUser kc.UserRepresentation

	t.Run("Nothing to update", func(t *testing.T) {
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
	})
	t.Run("Birth date update", func(t *testing.T) {
		var birthDateTxt = "15.06.2018"
		var birthDate, _ = time.Parse(constants.SupportedDateLayouts[0], "29.12.2019")
		user.BirthDate = &birthDate
		kcUser.SetAttributeString(constants.AttrbBirthDate, birthDateTxt)
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))

		birthDate, _ = time.Parse(constants.SupportedDateLayouts[0], birthDateTxt)
		user.BirthDate = &birthDate
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
	})
	t.Run("First name update", func(t *testing.T) {
		var name = "THE NAME"
		user.FirstName = ptr("OTHER NAME")
		kcUser.FirstName = &name
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))

		user.FirstName = &name
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
	})
	t.Run("Last name update", func(t *testing.T) {
		var name = "THE NAME"
		user.LastName = ptr("OTHER NAME")
		kcUser.LastName = &name
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))

		user.LastName = &name
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
	})
	t.Run("Gender update", func(t *testing.T) {
		var gender = "M"
		user.Gender = ptr("F")
		kcUser.SetAttributeString(constants.AttrbGender, gender)
		assert.True(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))

		user.Gender = ptr("m")
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
	})
	t.Run("Other fields does not matter", func(t *testing.T) {
		user.Email = ptr("any@mail.me")
		kcUser.Email = ptr("any.other@mail.me")
		assert.False(t, user.HasUpdateOfAccreditationDependantInformationKC(&kcUser))
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

func TestPendingChecksValidate(t *testing.T) {
	var (
		invalid = ""
	)

	t.Run("Valid use case", func(t *testing.T) {
		var check = createValidPendingChecks()
		assert.Nil(t, check.Validate(), "PendingChecks is expected to be valid")
	})

	var pendingChecks []PendingChecksRepresentation
	for i := 0; i < 2; i++ {
		pendingChecks = append(pendingChecks, createValidPendingChecks())
	}
	pendingChecks[0].Nature = nil
	pendingChecks[1].Nature = &invalid

	for idx, aCheck := range pendingChecks {
		t.Run(fmt.Sprintf("Invalid PendingChecks #%d", idx), func(t *testing.T) {
			assert.NotNil(t, aCheck.Validate())
		})
	}
}
