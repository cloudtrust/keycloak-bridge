package apiaccount

import (
	"context"
	"errors"
	"strings"
	"testing"

	csjson "github.com/cloudtrust/common-service/v2/json"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConvertCredential(t *testing.T) {
	var credKc kc.CredentialRepresentation
	var credType = "password"
	var credID = "123456"
	var configKc = "{}"

	credKc.Type = &credType
	credKc.ID = &credID
	credKc.CredentialData = nil

	assert.Equal(t, credKc.Type, ConvertCredential(&credKc).Type)
	assert.Equal(t, credKc.ID, ConvertCredential(&credKc).ID)
	assert.Nil(t, ConvertCredential(&credKc).CredentialData)

	credKc.CredentialData = &configKc
	assert.NotNil(t, ConvertCredential(&credKc).CredentialData)
	assert.Equal(t, "{}", *ConvertCredential(&credKc).CredentialData)
}

func TestConvertToAPIAccount(t *testing.T) {
	var ctx = context.TODO()
	var logger = log.NewNopLogger()

	var kcUser = kc.UserRepresentation{}
	assert.Nil(t, nil, ConvertToAPIAccount(ctx, kcUser, logger))

	t.Run("Empty attributes", func(t *testing.T) {
		var attributes = make(kc.Attributes)
		kcUser = kc.UserRepresentation{Attributes: &attributes}
		assert.Nil(t, nil, ConvertToAPIAccount(ctx, kcUser, logger).PhoneNumber)
	})

	var attributes = kc.Attributes{
		constants.AttrbPhoneNumber:         []string{"+41221234567"},
		constants.AttrbGender:              []string{"M"},
		constants.AttrbBirthDate:           []string{"15.02.1920"},
		constants.AttrbLocale:              []string{"fr"},
		constants.AttrbPhoneNumberVerified: []string{"true"},
		constants.AttrbAccreditations:      []string{`{"type":"one","expiryDate":"05.04.2020"}`, `{"type":"two","expiryDate":"05.03.2032"}`},
		constants.AttrbBusinessID:          []string{"123456789"},
	}

	t.Run("Check attributes are copied", func(t *testing.T) {
		kcUser = kc.UserRepresentation{Attributes: &attributes}
		var user = ConvertToAPIAccount(ctx, kcUser, logger)
		assert.Equal(t, "+41221234567", *user.PhoneNumber)
		assert.Equal(t, "M", *user.Gender)
		assert.Equal(t, "15.02.1920", *user.BirthDate)
		assert.Equal(t, "fr", *user.Locale)
		assert.True(t, *user.PhoneNumberVerified)
		assert.Len(t, *user.Accreditations, 2)
		assert.False(t, *(*user.Accreditations)[0].Revoked)
		assert.False(t, *(*user.Accreditations)[1].Revoked)
		assert.False(t, *(*user.Accreditations)[1].Expired)
		assert.Equal(t, "123456789", *user.BusinessID)
	})

	t.Run("PhoneNumberVerified is invalid", func(t *testing.T) {
		attributes.SetString(constants.AttrbPhoneNumberVerified, "vielleicht")
		var user = ConvertToAPIAccount(ctx, kcUser, logger)
		assert.Nil(t, user.PhoneNumberVerified)

		attributes.SetString(constants.AttrbPhoneNumberVerified, "true")
	})
	t.Run("Accreditations are revoked", func(t *testing.T) {
		attributes.Set(constants.AttrbAccreditations, []string{`{"type":"one","expiryDate":"05.04.2020"}`, `{"type":"two","expiryDate":"05.03.2039", "revoked": true}`})
		var user = ConvertToAPIAccount(ctx, kcUser, logger)
		assert.Len(t, *user.Accreditations, 2)
		assert.False(t, *(*user.Accreditations)[0].Revoked)
		assert.True(t, *(*user.Accreditations)[0].Expired)
		assert.True(t, *(*user.Accreditations)[1].Revoked)
		assert.False(t, *(*user.Accreditations)[1].Expired)
	})

	t.Run("Accreditations are invalid", func(t *testing.T) {
		attributes.SetString(constants.AttrbAccreditations, "{")
		var user = ConvertToAPIAccount(ctx, kcUser, logger)
		assert.Len(t, *user.Accreditations, 0)
	})
}

func TestConvertToKCUser(t *testing.T) {
	var apiUser = UpdatableAccountRepresentation{}
	assert.Nil(t, ConvertToKCUser(apiUser).Attributes)

	var phoneNumber = "+41221234567"
	var locale = "fr"
	var businessID = "123456789"
	var business = csjson.OptionalString{Defined: true, Value: &businessID}
	apiUser = UpdatableAccountRepresentation{PhoneNumber: &phoneNumber, Locale: &locale, BusinessID: business}
	var kcUser = ConvertToKCUser(apiUser)
	assert.Equal(t, phoneNumber, *kcUser.GetAttributeString(constants.AttrbPhoneNumber))
	assert.Equal(t, locale, *kcUser.GetAttributeString(constants.AttrbLocale))
	assert.Equal(t, businessID, *kcUser.GetAttributeString(constants.AttrbBusinessID))
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
	var user = UpdatableAccountRepresentation{}
	assert.Nil(t, user.GetField("not-existing-field"))
}

func testGetSetField(t *testing.T, fieldName string, value interface{}) {
	var user UpdatableAccountRepresentation
	t.Run("Field "+fieldName, func(t *testing.T) {
		assert.Nil(t, user.GetField(fieldName))
		user.SetField(fieldName, value)
		assert.Equal(t, value, *user.GetField(fieldName).(*string))
	})
}

type mockUserProfile struct {
}

func (up *mockUserProfile) GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error) {
	return kc.UserProfileRepresentation{}, errors.New("any error")
}

func TestValidateUpdatableAccountRepresentation(t *testing.T) {
	var user = UpdatableAccountRepresentation{}
	var realm = "the-realm"
	var ctx = context.TODO()

	var mup = &mockUserProfile{}
	assert.NotNil(t, user.Validate(ctx, mup, realm))
}

func TestValidateUpdatePasswordRepresentation(t *testing.T) {
	{
		password := createValidUpdatePasswordBody()
		assert.Nil(t, password.Validate())
	}

	value := ""

	{
		password := createValidUpdatePasswordBody()
		password.CurrentPassword = value
		assert.NotNil(t, password.Validate())
	}

	{
		password := createValidUpdatePasswordBody()
		password.NewPassword = value
		assert.NotNil(t, password.Validate())
	}

	{
		password := createValidUpdatePasswordBody()
		password.ConfirmPassword = value
		assert.NotNil(t, password.Validate())
	}

}

func TestValidateCredentialRepresentation(t *testing.T) {
	{
		credential := createValidCredentialRepresentation()
		assert.Nil(t, credential.Validate())
	}

	value := ""

	{
		credential := createValidCredentialRepresentation()
		credential.ID = &value
		assert.NotNil(t, credential.Validate())
	}

	{
		credential := createValidCredentialRepresentation()
		credential.Type = &value
		assert.NotNil(t, credential.Validate())
	}

	{
		tooLong := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" // 36 characters
		tooLong = tooLong + tooLong + tooLong             // 108 characters
		tooLong = tooLong + tooLong + tooLong             // 324 characters
		credential := createValidCredentialRepresentation()
		credential.UserLabel = &tooLong
		assert.NotNil(t, credential.Validate())
	}
}

func createValidUpdatePasswordBody() UpdatePasswordBody {
	password := "password"

	return UpdatePasswordBody{
		CurrentPassword: password,
		NewPassword:     password,
		ConfirmPassword: password,
	}
}

func createValidCredentialRepresentation() CredentialRepresentation {
	id := "f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"
	credType := "otp"
	userLabel := "my otp"
	credData := "{}"

	return CredentialRepresentation{
		ID:             &id,
		Type:           &credType,
		CredentialData: &credData,
		UserLabel:      &userLabel,
	}
}
