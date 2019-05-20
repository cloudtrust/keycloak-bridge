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

	// Locale
	assert.Nil(t, ConvertToAPIUser(kcUser).Locale)
	kcUser.Attributes = &m
	m["locale"] = []string{"en"}
	assert.NotNil(t, *ConvertToAPIUser(kcUser).Locale)
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

	// Locale
	var locale = "it"
	user.Locale = &locale
	assert.Equal(t, locale, (*ConvertToKCUser(user).Attributes)["locale"][0])
}

func TestValidateUserRepresentation(t *testing.T) {
	{
		user := createValidUserRepresentation()
		assert.Nil(t, user.Validate())
	}

	id := "#12345"
	username := "username!"
	email := "usernamcompany.com"
	phoneNumber := "415174234"
	firstName := "Firstname!"
	lastName := "Lastname]"
	label := ""
	gender := "Male"
	birthDate := "1990-13-28"
	locale := "english"
	groups := []string{"f467ed7c", "7767ed7c-0a1d-4eee-9bb8-669c6f89c007"}
	roles := []string{"abcded7", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}

	var users []UserRepresentation
	for i := 0; i < 12; i++ {
		users = append(users, createValidUserRepresentation())
	}

	users[0].Id = &id
	users[1].Username = &username
	users[2].Email = &email
	users[3].PhoneNumber = &phoneNumber
	users[4].FirstName = &firstName
	users[5].LastName = &lastName
	users[6].Label = &label
	users[7].Gender = &gender
	users[8].BirthDate = &birthDate
	users[9].Groups = &groups
	users[10].Roles = &roles
	users[11].Locale = &locale

	for _, user := range users {
		assert.NotNil(t, user.Validate())
	}
}

func TestValidateRoleRepresentation(t *testing.T) {
	{
		role := createValidRoleRepresentation()
		assert.Nil(t, role.Validate())
	}

	id := "f467ed7c"
	name := "name *"
	description := ""

	var roles []RoleRepresentation
	for i := 0; i < 4; i++ {
		roles = append(roles, createValidRoleRepresentation())
	}

	roles[0].Id = &id
	roles[1].Name = &name
	roles[2].Description = &description
	roles[3].ContainerId = &id

	for _, role := range roles {
		assert.NotNil(t, role.Validate())
	}
}

func TestValidatePasswordRepresentation(t *testing.T) {
	{
		password := createValidPasswordRepresentation()
		assert.Nil(t, password.Validate())
	}

	value := ""
	password := createValidPasswordRepresentation()
	password.Value = &value

	assert.NotNil(t, password.Validate())

}

func TestValidateRealmCustomConfiguration(t *testing.T) {
	{
		config := createValidRealmCustomConfiguration()
		assert.Nil(t, config.Validate())
	}

	defaultClientID := "f467ed7c"
	defaultRedirectURI := "ht//tp://company.com"

	var configs []RealmCustomConfiguration
	for i := 0; i < 2; i++ {
		configs = append(configs, createValidRealmCustomConfiguration())
	}

	configs[0].DefaultClientId = &defaultClientID
	configs[1].DefaultRedirectUri = &defaultRedirectURI

	for _, config := range configs {
		assert.NotNil(t, config.Validate())
	}
}

func TestValidateRequiredAction(t *testing.T) {
	{
		action := createValidRequiredAction()
		assert.Nil(t, action.Validate())
	}

	action := RequiredAction("^")
	assert.NotNil(t, action.Validate())
}

func createValidUserRepresentation() UserRepresentation {
	var groups = []string{"f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee", "7767ed7c-0a1d-4eee-9bb8-669c6f89c007"}
	var roles = []string{"abcded7c-0a1d-4eee-9bb8-669c6f89c0ee", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}

	id := "f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"
	username := "username"
	email := "username@company.com"
	boolTrue := true
	phoneNumber := "+415174234"
	firstName := "Firstname"
	lastName := "Lastname"
	label := "label"
	gender := "F"
	birthDate := "1990-12-28"
	locale := "en"

	var user = UserRepresentation{}
	user.Id = &id
	user.Username = &username
	user.Email = &email
	user.Enabled = &boolTrue
	user.EmailVerified = &boolTrue
	user.PhoneNumber = &phoneNumber
	user.PhoneNumberVerified = &boolTrue
	user.FirstName = &firstName
	user.LastName = &lastName
	user.Label = &label
	user.Gender = &gender
	user.BirthDate = &birthDate
	user.Groups = &groups
	user.Roles = &roles
	user.Locale = &locale

	return user
}

func createValidRoleRepresentation() RoleRepresentation {
	id := "f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"
	name := "name"
	description := "description"
	boolTrue := true

	var role = RoleRepresentation{}
	role.Id = &id
	role.Name = &name
	role.Description = &description
	role.ContainerId = &id
	role.ClientRole = &boolTrue
	role.Composite = &boolTrue

	return role
}

func createValidPasswordRepresentation() PasswordRepresentation {
	password := "password"

	return PasswordRepresentation{
		Value: &password,
	}
}

func createValidRealmCustomConfiguration() RealmCustomConfiguration {
	defaultClientID := "f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"
	defaultRedirectURI := "http://company.com"

	return RealmCustomConfiguration{
		DefaultClientId:    &defaultClientID,
		DefaultRedirectUri: &defaultRedirectURI,
	}
}

func createValidRequiredAction() RequiredAction {
	return RequiredAction("verify-email")
}
