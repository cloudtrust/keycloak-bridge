package account

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestConvertCredential(t *testing.T) {
	var credKc kc.CredentialRepresentation
	var credType = "password"
	var credID = "123456"
	var configKc = "{}"

	credKc.Type = &credType
	credKc.Id = &credID
	credKc.CredentialData = nil

	assert.Equal(t, credKc.Type, ConvertCredential(&credKc).Type)
	assert.Equal(t, credKc.Id, ConvertCredential(&credKc).ID)
	assert.Nil(t, ConvertCredential(&credKc).CredentialData)

	credKc.CredentialData = &configKc
	assert.NotNil(t, ConvertCredential(&credKc).CredentialData)
	assert.Equal(t, "{}", *ConvertCredential(&credKc).CredentialData)
}

func TestConvertToAPIAccount(t *testing.T) {
	var kcUser = kc.UserRepresentation{}
	assert.Nil(t, nil, ConvertToAPIAccount(kcUser))

	var attributes = make(map[string][]string)
	kcUser = kc.UserRepresentation{Attributes: &attributes}
	assert.Nil(t, nil, ConvertToAPIAccount(kcUser).PhoneNumber)

	attributes["phoneNumber"] = []string{"+41221234567"}
	kcUser = kc.UserRepresentation{Attributes: &attributes}
	assert.Equal(t, "+41221234567", *ConvertToAPIAccount(kcUser).PhoneNumber)
}

func TestConvertToKCUser(t *testing.T) {
	var apiUser = AccountRepresentation{}
	assert.Nil(t, ConvertToKCUser(apiUser).Attributes)

	var phoneNumber = "+41221234567"
	apiUser = AccountRepresentation{PhoneNumber: &phoneNumber}
	var kcUser = ConvertToKCUser(apiUser)
	var kcAttributes = *kcUser.Attributes
	assert.Equal(t, phoneNumber, kcAttributes["phoneNumber"][0])
}

func TestValidateAccountRepresentation(t *testing.T) {
	var invalidName = ""
	var invalidEmail = "bobby-at-mail.com"
	var invalidPhone = "+412212345AB"
	var accounts []AccountRepresentation

	for i := 0; i < 5; i++ {
		accounts = append(accounts, createValidAccountRepresentation())
	}

	assert.Nil(t, accounts[0].Validate())

	accounts[0].Username = &invalidName
	accounts[1].FirstName = &invalidName
	accounts[2].LastName = &invalidName
	accounts[3].Email = &invalidEmail
	accounts[4].PhoneNumber = &invalidPhone

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
	var validName = "Bobby"
	var validEmail = "bobby@mail.com"
	var validPhone = "+41221234567"

	return AccountRepresentation{
		Username:    &validName,
		FirstName:   &validName,
		LastName:    &validName,
		Email:       &validEmail,
		PhoneNumber: &validPhone,
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
