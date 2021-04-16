package apikyc

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"

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
		country         = "CH"
		idDocType       = "PASSPORT"
		idDocNumber     = "123456789"
		idDocExpiration = "23.02.2039"
		locale          = "fr"
		businessID      = "123456789"
		accred1         = AccreditationRepresentation{Type: ptr("short"), ExpiryDate: ptr("31.12.2024")}
		accred2         = AccreditationRepresentation{Type: ptr("long"), ExpiryDate: ptr("31.12.2039")}
		creds           = []AccreditationRepresentation{accred1, accred2}
		attachments     = []AttachmentRepresentation{createValidAttachment()}
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
		Nationality:          &country,
		IDDocumentType:       &idDocType,
		IDDocumentNumber:     &idDocNumber,
		IDDocumentExpiration: &idDocExpiration,
		IDDocumentCountry:    &country,
		Locale:               &locale,
		BusinessID:           &businessID,
		Accreditations:       &creds,
		Attachments:          &attachments,
	}
}

func createValidAttachment() AttachmentRepresentation {
	var (
		contentBase  = "basicvalueofsomecharacters"
		contentBytes = []byte(contentBase + contentBase + contentBase + contentBase)
	)
	return AttachmentRepresentation{Filename: ptr("filename.pdf"), ContentType: ptr("application/pdf"), Content: &contentBytes}
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
			constants.AttrbLocale:              []string{"de"},
			constants.AttrbBusinessID:          []string{"123456789"},
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

func TestExportToDBUser(t *testing.T) {
	var user = createValidUser()
	var dbUser = dto.DBUser{}

	user.ExportToDBUser(&dbUser)

	assert.Equal(t, user.BirthLocation, dbUser.BirthLocation)
	assert.Equal(t, user.IDDocumentCountry, dbUser.IDDocumentCountry)
	assert.Equal(t, user.IDDocumentExpiration, dbUser.IDDocumentExpiration)
	assert.Equal(t, user.IDDocumentNumber, dbUser.IDDocumentNumber)
	assert.Equal(t, user.IDDocumentType, dbUser.IDDocumentType)
	assert.Equal(t, user.Nationality, dbUser.Nationality)
	assert.Equal(t, user.ID, dbUser.UserID)
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
		assert.Equal(t, *user.Locale, *kcUser.GetAttributeString(constants.AttrbLocale))
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
		invalidDate = "29.02.2019"
	)

	t.Run("Valid users with an attachment", func(t *testing.T) {
		var user = createValidUser()
		assert.Nil(t, user.Validate(), "User is expected to be valid")
	})
	t.Run("Valid users without attachment", func(t *testing.T) {
		var user = createValidUser()
		user.Attachments = nil
		assert.Nil(t, user.Validate(), "User is expected to be valid")
	})
	var users []UserRepresentation
	for i := 0; i < 18; i++ {
		users = append(users, createValidUser())
	}
	// invalid values
	users[0].Gender = &empty
	users[1].FirstName = &empty
	users[2].LastName = &empty
	users[3].BirthDate = &invalidDate
	users[4].BirthLocation = &empty
	users[5].Nationality = &empty
	users[6].IDDocumentType = &empty
	users[7].IDDocumentNumber = &empty
	users[8].IDDocumentExpiration = &invalidDate
	users[9].IDDocumentCountry = &empty
	users[10].BusinessID = &empty
	// mandatory parameters
	users[11].Gender = nil
	users[12].FirstName = nil
	users[13].LastName = nil
	users[14].BirthDate = nil
	users[15].IDDocumentNumber = nil
	var newAttachments = append(*users[15].Attachments, AttachmentRepresentation{})
	users[16].Attachments = &newAttachments
	var oneByte = []byte{0}
	(*users[17].Attachments)[0].Content = &oneByte

	for idx, aUser := range users {
		t.Run(fmt.Sprintf("Invalid users %d", idx), func(t *testing.T) {
			assert.NotNil(t, aUser.Validate(), "User is expected to be invalid with user %s", aUser.UserToJSON())
		})
	}
}

func TestValidateAttachment(t *testing.T) {
	t.Run("Valid attachment", func(t *testing.T) {
		var attachment = createValidAttachment()
		assert.Nil(t, attachment.Validate())
	})
	t.Run("Successful evaluation of content type", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.Filename = ptr("image.jpg")
		attachment.ContentType = nil
		assert.Nil(t, attachment.Validate())
		assert.Equal(t, "image/jpeg", *attachment.ContentType)
	})
	t.Run("Missing both filename and content type", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.Filename = nil
		attachment.ContentType = nil
		assert.NotNil(t, attachment.Validate())
	})
	t.Run("Invalid content type", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.ContentType = ptr("not-a-valid-content-type")
		assert.NotNil(t, attachment.Validate())
	})
	t.Run("Can't find known content type from filename", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.Filename = ptr("image.gif")
		attachment.ContentType = nil
		assert.NotNil(t, attachment.Validate())
	})
	t.Run("Unsupported content type", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.Filename = nil
		attachment.ContentType = ptr("text/plain")
		assert.NotNil(t, attachment.Validate())
	})
	t.Run("Invalid content length", func(t *testing.T) {
		var attachment = createValidAttachment()
		var bytes = []byte{1, 2, 3}
		attachment.Content = &bytes
		assert.NotNil(t, attachment.Validate())
	})
}
