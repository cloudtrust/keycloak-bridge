package apivalidation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/common-service/v2/fields"

	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func ptr(v string) *string {
	return &v
}

func createValidAccreditation() AccreditationRepresentation {
	return AccreditationRepresentation{
		Name:     ptr("EPR"),
		Validity: ptr("4y"),
	}
}

func createValidUser() UserRepresentation {
	var (
		bFalse          = false
		birthDate       = time.Now()
		idDocExpiration = time.Now()
	)

	return UserRepresentation{
		Username:             ptr("46791834"),
		Gender:               ptr("M"),
		FirstName:            ptr("Marc"),
		LastName:             ptr("El-Bichoun"),
		Email:                ptr("marcel.bichon@elca.ch"),
		EmailVerified:        &bFalse,
		PhoneNumber:          ptr("00 33 686 550011"),
		PhoneNumberVerified:  &bFalse,
		BirthDate:            &birthDate,
		BirthLocation:        ptr("Bermuda, CH"),
		Nationality:          ptr("DE"),
		IDDocumentType:       ptr("PASSPORT"),
		IDDocumentNumber:     ptr("123456789"),
		IDDocumentExpiration: &idDocExpiration,
		IDDocumentCountry:    ptr("CH"),
	}
}

func createValidKeycloakUser() kc.UserRepresentation {
	var (
		bTrue = true
	)

	return kc.UserRepresentation{
		Attributes: &kc.Attributes{
			constants.AttrbGender:              []string{"M"},
			constants.AttrbPhoneNumber:         []string{"00 33 686 550011"},
			constants.AttrbPhoneNumberVerified: []string{"true"},
			constants.AttrbBirthDate:           []string{"29.02.2020"},
		},
		FirstName:     ptr("Marc"),
		LastName:      ptr("El-Bichoun"),
		Email:         ptr("marcel.bichon@elca.ch"),
		EmailVerified: &bTrue,
	}
}

func TestValidateAccreditation(t *testing.T) {
	t.Run("Success case", func(t *testing.T) {
		var accred = createValidAccreditation()
		assert.Nil(t, accred.Validate())
	})

	var accreds []AccreditationRepresentation
	for i := 0; i < 4; i++ {
		accreds = append(accreds, createValidAccreditation())
	}
	accreds[0].Name = nil
	accreds[1].Name = ptr("")
	accreds[2].Validity = nil
	accreds[3].Validity = ptr("not a validity")

	for idx, accred := range accreds {
		t.Run(fmt.Sprintf("Failure test #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, accred.Validate())
		})
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

type mockUserProfile struct {
	err error
}

func (m *mockUserProfile) GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error) {
	return kc.UserProfileRepresentation{}, m.err
}

func TestUserValidate(t *testing.T) {
	var (
		user  = createValidUser()
		realm = "the-realm"
		ctx   = context.TODO()
	)

	t.Run("User is invalid", func(t *testing.T) {
		assert.NotNil(t, user.Validate(ctx, &mockUserProfile{err: errors.New("")}, realm))
	})
	t.Run("User is valid", func(t *testing.T) {
		assert.Nil(t, user.Validate(ctx, &mockUserProfile{}, realm))
	})
}

func TestGetSetField(t *testing.T) {
	for _, field := range []string{
		"username:12345678", "email:name@domain.ch", "firstName:firstname", "lastName:lastname", "ENC_gender:M", "phoneNumber:+41223145789",
		"ENC_birthDate:12.11.2010", "ENC_birthLocation:chezouam", "ENC_nationality:ch", "ENC_idDocumentType:PASSPORT", "ENC_idDocumentNumber:123-456-789",
		"ENC_idDocumentExpiration:01.01.2039", "ENC_idDocumentCountry:ch", "locale:fr",
	} {
		var parts = strings.Split(field, ":")
		testGetSetField(t, parts[0], parts[1])
	}
	var user = UserRepresentation{}
	assert.Nil(t, user.GetField("not-existing-field"))
}

func testGetSetField(t *testing.T, fieldName string, value interface{}) {
	var user UserRepresentation
	t.Run("Field "+fieldName, func(t *testing.T) {
		assert.Nil(t, user.GetField(fieldName))
		user.SetField(fieldName, value)
		assert.NotNil(t, user.GetField(fieldName))
	})
}

func TestHasKCChanges(t *testing.T) {
	var user UserRepresentation
	var kcUser kc.UserRepresentation

	t.Run("Nothing to update", func(t *testing.T) {
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Birth date update", func(t *testing.T) {
		var birthDateTxt = "15.06.2018"
		var birthDate, _ = time.Parse(constants.SupportedDateLayouts[0], "29.12.2019")
		user.BirthDate = &birthDate
		kcUser.SetAttributeString(constants.AttrbBirthDate, birthDateTxt)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		birthDate, _ = time.Parse(constants.SupportedDateLayouts[0], birthDateTxt)
		user.BirthDate = &birthDate
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("First name update", func(t *testing.T) {
		var name = "THE NAME"
		user.FirstName = ptr("OTHER NAME")
		kcUser.FirstName = &name
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.FirstName = &name
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Last name update", func(t *testing.T) {
		var name = "THE NAME"
		user.LastName = ptr("OTHER NAME")
		kcUser.LastName = &name
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.LastName = &name
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Gender update", func(t *testing.T) {
		var gender = "M"
		user.Gender = ptr("F")
		kcUser.SetAttributeString(constants.AttrbGender, gender)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.Gender = ptr("m")
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Other fields does not matter", func(t *testing.T) {
		user.Email = ptr("any@mail.me")
		kcUser.Email = ptr("any.other@mail.me")
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})

	t.Run("Expiry date update", func(t *testing.T) {
		var expiryTxt = "15.06.2018"
		var expiry, _ = time.Parse(constants.SupportedDateLayouts[0], "29.12.2019")
		user.IDDocumentExpiration = &expiry
		kcUser.SetAttributeString(constants.AttrbIDDocumentExpiration, expiryTxt)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		expiry, _ = time.Parse(constants.SupportedDateLayouts[0], expiryTxt)
		user.IDDocumentExpiration = &expiry
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Nationality", func(t *testing.T) {
		var nationality = "TYPE1"
		user.Nationality = ptr("OTHER-NATIONALITY")
		kcUser.SetAttributeString(constants.AttrbNationality, nationality)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.Nationality = &nationality
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Document type update", func(t *testing.T) {
		var documentType = "TYPE1"
		user.IDDocumentType = ptr("OTHER-TYPE")
		kcUser.SetAttributeString(constants.AttrbIDDocumentType, documentType)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.IDDocumentType = &documentType
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Document number update", func(t *testing.T) {
		var documentNumber = "1234567890"
		user.IDDocumentNumber = ptr("OTHER-NUMBER")
		kcUser.SetAttributeString(constants.AttrbIDDocumentNumber, documentNumber)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.IDDocumentNumber = &documentNumber
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Document country update", func(t *testing.T) {
		var documentCountry = "DE"
		user.IDDocumentCountry = ptr("CH")
		kcUser.SetAttributeString(constants.AttrbIDDocumentCountry, documentCountry)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.IDDocumentCountry = &documentCountry
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
	t.Run("Birth location update", func(t *testing.T) {
		var birthLocation = "Where"
		user.BirthLocation = ptr("Here !")
		kcUser.SetAttributeString(constants.AttrbBirthLocation, birthLocation)
		fc := user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.True(t, fc.IsAnyFieldUpdated())

		user.BirthLocation = &birthLocation
		fc = user.UpdateFieldsComparatorWithKCFields(fields.NewFieldsComparator(), &kcUser)
		assert.False(t, fc.IsAnyFieldUpdated())
	})
}
