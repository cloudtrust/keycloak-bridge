package apikyc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func ptr(value string) *string {
	return &value
}

func createValidUser(dynamicAttribute string) UserRepresentation {
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
		dynamicValue    = "customValue"
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
		Dynamic:              map[string]any{dynamicAttribute: dynamicValue},
	}
}

func createValidAttachment() AttachmentRepresentation {
	var (
		contentBase  = "basicvalueofsomecharacters"
		contentBytes = []byte(contentBase + contentBase + contentBase + contentBase)
	)
	return AttachmentRepresentation{Filename: ptr("filename.pdf"), ContentType: ptr("application/pdf"), Content: &contentBytes}
}

func createValidKeycloakUser(dynamicAttribute string) kc.UserRepresentation {
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
			kc.AttributeKey(dynamicAttribute):  []string{"customValue"},
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

func TestExportToKeycloak(t *testing.T) {
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
	t.Run("Empty user from Keycloak", func(t *testing.T) {
		var user = createValidUser(customAttribute)
		var kcUser = kc.UserRepresentation{}

		user.ExportToKeycloak(&kcUser, profile)

		assert.Equal(t, user.FirstName, kcUser.FirstName)
		assert.Equal(t, user.LastName, kcUser.LastName)
		assert.Equal(t, user.Email, kcUser.Email)
		assert.False(t, *kcUser.EmailVerified)
		assert.True(t, *kcUser.Enabled)
		assert.Equal(t, user.BirthLocation, kcUser.Attributes.GetString(constants.AttrbBirthLocation))
		assert.Equal(t, user.IDDocumentCountry, kcUser.Attributes.GetString(constants.AttrbIDDocumentCountry))
		assert.Equal(t, user.IDDocumentExpiration, kcUser.Attributes.GetString(constants.AttrbIDDocumentExpiration))
		assert.Equal(t, user.IDDocumentNumber, kcUser.Attributes.GetString(constants.AttrbIDDocumentNumber))
		assert.Equal(t, user.IDDocumentType, kcUser.Attributes.GetString(constants.AttrbIDDocumentType))
		assert.Equal(t, user.Nationality, kcUser.Attributes.GetString(constants.AttrbNationality))
		assert.Equal(t, user.Dynamic[customAttribute], kcUser.GetDynamicAttributes(profile)[customAttribute])
	})

	t.Run("Empty user from API", func(t *testing.T) {
		var user = UserRepresentation{}
		var kcUser = createValidKeycloakUser(customAttribute)

		user.ExportToKeycloak(&kcUser, profile)

		assert.True(t, *kcUser.EmailVerified)
		assert.Equal(t, "true", (*kcUser.Attributes)["phoneNumberVerified"][0])
		assert.True(t, *kcUser.Enabled)
	})

	t.Run("Updates both email and phone", func(t *testing.T) {
		var user = createValidUser(customAttribute)
		var kcUser = createValidKeycloakUser(customAttribute)
		var newEmail = "new-address@cloudtrust.io"
		var newPhoneNumber = "00 41 22 345 45 78"
		var verified = true
		user.Email = &newEmail
		user.PhoneNumber = &newPhoneNumber
		// Verified flags from api.UserRepresentation must be ignored
		user.EmailVerified = &verified
		user.PhoneNumberVerified = &verified

		user.ExportToKeycloak(&kcUser, profile)

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
	var kcUser = createValidKeycloakUser(customAttribute)
	kcUser.SetAttributeBool(constants.AttrbPhoneNumberVerified, true)

	// Add an invalid JSON accreditation: it will be ignored
	var accreds = append(kcUser.Attributes.Get(constants.AttrbAccreditations), "{")
	kcUser.Attributes.Set(constants.AttrbAccreditations, accreds)
	assert.Equal(t, 3, len(kcUser.Attributes.Get(constants.AttrbAccreditations)))

	var imported = UserRepresentation{}

	imported.ImportFromKeycloak(ctx, &kcUser, profile, logger)

	assert.Equal(t, *kcUser.FirstName, *imported.FirstName)
	assert.Equal(t, *kcUser.LastName, *imported.LastName)
	assert.Equal(t, *kcUser.GetAttributeString(constants.AttrbGender), *imported.Gender)
	assert.Len(t, *imported.Accreditations, 2)
	assert.True(t, *imported.PhoneNumberVerified)
	assert.Equal(t, kcUser.GetDynamicAttributes(profile)[customAttribute], imported.Dynamic[customAttribute])
}

type mockUserProfile struct {
	err error
}

func (up *mockUserProfile) GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error) {
	return kc.UserProfileRepresentation{}, up.err
}

func TestValidateUserRepresentation(t *testing.T) {
	var mup = &mockUserProfile{err: nil}
	var realm = "the-realm"
	var ctx = context.TODO()

	t.Run("UserProfile fails", func(t *testing.T) {
		var mupFails = &mockUserProfile{err: errors.New("any error")}
		var user = createValidUser("")
		assert.NotNil(t, user.Validate(ctx, mupFails, realm), "User is expected to be valid")
	})
	t.Run("Valid users with an attachment", func(t *testing.T) {
		var user = createValidUser("")
		assert.Nil(t, user.Validate(ctx, mup, realm), "User is expected to be valid")
	})
	t.Run("Valid users without attachment", func(t *testing.T) {
		var user = createValidUser("")
		user.Attachments = nil
		assert.Nil(t, user.Validate(ctx, mup, realm), "User is expected to be valid")
	})
	t.Run("Valid users with max attachments", func(t *testing.T) {
		var user = createValidUser("")
		var attachment []AttachmentRepresentation
		for i := 0; i < maxNumberAttachments; i++ {
			attachment = append(attachment, createValidAttachment())
		}
		user.Attachments = &attachment
		assert.Nil(t, user.Validate(ctx, mup, realm), "User is expected to be valid")
	})
	t.Run("Valid users with too many attachments", func(t *testing.T) {
		var user = createValidUser("")
		var attachment []AttachmentRepresentation
		for i := 0; i < maxNumberAttachments+1; i++ {
			attachment = append(attachment, createValidAttachment())
		}
		user.Attachments = &attachment
		assert.NotNil(t, user.Validate(ctx, mup, realm), "User is expected to be invalid")
	})
	t.Run("Valid users everything optional", func(t *testing.T) {
		var user UserRepresentation
		assert.Nil(t, user.Validate(ctx, mup, realm))
	})
	t.Run("User has invalid attachement", func(t *testing.T) {
		var user UserRepresentation
		var attachments = []AttachmentRepresentation{{}}
		user.Attachments = &attachments
		assert.NotNil(t, user.Validate(ctx, mup, realm))
	})
}

func TestGetSetField(t *testing.T) {
	for _, field := range []string{
		"username:12345678", "email:name@domain.ch", "firstName:firstname", "lastName:lastname", "ENC_gender:M", "phoneNumber:+41223145789",
		"ENC_birthDate:12.11.2010", "ENC_birthLocation:chezouam", "ENC_nationality:ch", "ENC_idDocumentType:PASSPORT", "ENC_idDocumentNumber:123-456-789",
		"ENC_idDocumentExpiration:01.01.2039", "ENC_idDocumentCountry:ch", "locale:fr", "businessID:456789",
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
		assert.Equal(t, value, *user.GetField(fieldName).(*string))
	})
}

func TestValidateAttachment(t *testing.T) {
	t.Run("Valid attachment", func(t *testing.T) {
		var attachment = createValidAttachment()
		assert.Nil(t, attachment.Validate())
	})
	t.Run("Successful evaluation of content type", func(t *testing.T) {
		var attachment = createValidAttachment()
		attachment.Filename = ptr("image.JPG")
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
