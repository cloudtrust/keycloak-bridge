package apiaccount

import (
	"context"
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
		constants.AttrbPendingChecks:       []string{`{"check-3": 123456789}`},
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
		assert.Len(t, *user.PendingChecks, 1)
		assert.Equal(t, "check-3", (*user.PendingChecks)[0])
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

func TestValidateAccountRepresentation(t *testing.T) {
	var invalidName = ""
	var invalidEmail = "bobby-at-mail.com"
	var invalidPhone = "+412212345AB"
	var invalidLocale = "fr-123"
	var accounts []AccountRepresentation

	for i := 0; i < 6; i++ {
		accounts = append(accounts, createValidAccountRepresentation())
	}

	assert.Nil(t, accounts[0].Validate())

	accounts[0].Username = &invalidName
	accounts[1].FirstName = &invalidName
	accounts[2].LastName = &invalidName
	accounts[3].Email = &invalidEmail
	accounts[4].PhoneNumber = &invalidPhone
	accounts[5].Locale = &invalidLocale

	for _, account := range accounts {
		assert.NotNil(t, account.Validate())
	}
}

func TestValidateUpdatableAccountRepresentation(t *testing.T) {
	var invalidName = ""
	var invalidEmail = "bobby-at-mail.com"
	var invalidPhone = "+412212345AB"
	var invalidLocale = "fr-123"
	var accounts []UpdatableAccountRepresentation

	for i := 0; i < 6; i++ {
		accounts = append(accounts, createValidUpdatableAccountRepresentation())
	}

	assert.Nil(t, accounts[0].Validate())

	accounts[0].Username = &invalidName
	accounts[1].FirstName = &invalidName
	accounts[2].LastName = &invalidName
	accounts[3].Email = &invalidEmail
	accounts[4].PhoneNumber = &invalidPhone
	accounts[5].Locale = &invalidLocale

	for _, account := range accounts {
		assert.NotNil(t, account.Validate())
	}
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

func createValidAccountRepresentation() AccountRepresentation {
	var validUserName = "bobby"
	var validName = "Bobby"
	var validEmail = "bobby@mail.com"
	var validPhone = "+41221234567"
	var validLocale = "fr"

	return AccountRepresentation{
		Username:    &validUserName,
		FirstName:   &validName,
		LastName:    &validName,
		Email:       &validEmail,
		PhoneNumber: &validPhone,
		Locale:      &validLocale,
	}
}

func createValidUpdatableAccountRepresentation() UpdatableAccountRepresentation {
	var validUserName = "bobby"
	var validName = "Bobby"
	var validEmail = "bobby@mail.com"
	var validPhone = "+41221234567"
	var validLocale = "fr"

	return UpdatableAccountRepresentation{
		Username:    &validUserName,
		FirstName:   &validName,
		LastName:    &validName,
		Email:       &validEmail,
		PhoneNumber: &validPhone,
		Locale:      &validLocale,
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
