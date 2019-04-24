package management_api

import (
	"testing"

	kc "github.com/cloudtrust/keycloak-client"
	"github.com/stretchr/testify/assert"
)

func TestConvertCredential(t *testing.T) {
	var credKc kc.CredentialRepresentation
	var credType = "password"
	var credID = "123456"
	var configKc map[string][]string
	configKc = make(map[string][]string)
	configKc["undesired_Key"] = make([]string, 0)
	configKc["deviceInfo_Model"] = make([]string, 0)

	credKc.Type = &credType
	credKc.Id = &credID
	credKc.Config = nil

	assert.Equal(t, credKc.Type, ConvertCredential(&credKc).Type)
	assert.Equal(t, credKc.Id, ConvertCredential(&credKc).Id)
	assert.Nil(t, ConvertCredential(&credKc).Config)

	credKc.Config = &configKc
	assert.NotNil(t, ConvertCredential(&credKc).Config)
	assert.Equal(t, 1, len(*ConvertCredential(&credKc).Config))
}

func TestConvertToAPIUser(t *testing.T) {
	var kcUser kc.UserRepresentation
	m := make(map[string][]string)

	// Phone number
	assert.Nil(t, ConvertToAPIUser(kcUser).PhoneNumber)
	kcUser.Attributes = &m
	m["phoneNumber"] = []string{"+4122555555"}
	assert.NotNil(t, ConvertToAPIUser(kcUser).PhoneNumber)

	// Label
	assert.Nil(t, ConvertToAPIUser(kcUser).Label)
	kcUser.Attributes = &m
	m["label"] = []string{"a label"}
	assert.NotNil(t, ConvertToAPIUser(kcUser).Label)

	// Gender
	assert.Nil(t, ConvertToAPIUser(kcUser).Gender)
	kcUser.Attributes = &m
	m["gender"] = []string{"a gender"}
	assert.NotNil(t, ConvertToAPIUser(kcUser).Gender)

	// Birthdate
	assert.Nil(t, ConvertToAPIUser(kcUser).BirthDate)
	kcUser.Attributes = &m
	m["birthDate"] = []string{"25/12/0"}
	assert.NotNil(t, ConvertToAPIUser(kcUser).BirthDate)

	// PhoneNumberVerified
	assert.Nil(t, ConvertToAPIUser(kcUser).PhoneNumberVerified)
	kcUser.Attributes = &m
	m["phoneNumberVerified"] = []string{"true"}
	assert.True(t, *ConvertToAPIUser(kcUser).PhoneNumberVerified)
}

func TestConvertToKCUser(t *testing.T) {
	var user UserRepresentation

	// Phone number
	assert.Nil(t, ConvertToKCUser(user).Attributes)
	var phoneNumber = "+4122555555"
	user.PhoneNumber = &phoneNumber
	assert.Equal(t, phoneNumber, (*ConvertToKCUser(user).Attributes)["phoneNumber"][0])

	// Label
	var label = "a label"
	user.Label = &label
	assert.Equal(t, label, (*ConvertToKCUser(user).Attributes)["label"][0])

	// Gender
	var gender = "a gender"
	user.Gender = &gender
	assert.Equal(t, gender, (*ConvertToKCUser(user).Attributes)["gender"][0])

	// Birthdate
	var date = "25/12/0"
	user.BirthDate = &date
	assert.Equal(t, date, (*ConvertToKCUser(user).Attributes)["birthDate"][0])

	// PhoneNumberVerified
	var verified = true
	user.PhoneNumberVerified = &verified
	assert.Equal(t, "true", (*ConvertToKCUser(user).Attributes)["phoneNumberVerified"][0])
}
