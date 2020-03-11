package management_api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/keycloak-bridge/internal/constants"
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

func TestConvertToAPIUser(t *testing.T) {
	var kcUser kc.UserRepresentation
	m := make(kc.Attributes)

	// Phone number
	assert.Nil(t, ConvertToAPIUser(kcUser).PhoneNumber)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbPhoneNumber, "+4122555555")
	assert.NotNil(t, ConvertToAPIUser(kcUser).PhoneNumber)

	// Label
	assert.Nil(t, ConvertToAPIUser(kcUser).Label)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbLabel, "a label")
	assert.NotNil(t, ConvertToAPIUser(kcUser).Label)

	// Gender
	assert.Nil(t, ConvertToAPIUser(kcUser).Gender)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbGender, "a gender")
	assert.NotNil(t, ConvertToAPIUser(kcUser).Gender)

	// Birthdate
	assert.Nil(t, ConvertToAPIUser(kcUser).BirthDate)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbBirthDate, "25/12/0")
	assert.NotNil(t, ConvertToAPIUser(kcUser).BirthDate)

	// PhoneNumberVerified
	assert.Nil(t, ConvertToAPIUser(kcUser).PhoneNumberVerified)
	kcUser.Attributes = &m
	m.SetBool(constants.AttrbPhoneNumberVerified, true)
	assert.True(t, *ConvertToAPIUser(kcUser).PhoneNumberVerified)

	// Locale
	assert.Nil(t, ConvertToAPIUser(kcUser).Locale)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbLocale, "en")
	assert.NotNil(t, *ConvertToAPIUser(kcUser).Locale)

	// SmsSent
	assert.Nil(t, ConvertToAPIUser(kcUser).SmsSent)
	kcUser.Attributes = &m
	m.SetInt(constants.AttrbSmsSent, 0)
	m["smsSent"] = []string{"0"}
	assert.NotNil(t, *ConvertToAPIUser(kcUser).SmsSent)

	// trustID groups
	assert.Nil(t, ConvertToAPIUser(kcUser).TrustIDGroups)
	kcUser.Attributes = &m
	m.SetString(constants.AttrbTrustIDGroups, "en")
	assert.NotNil(t, *ConvertToAPIUser(kcUser).TrustIDGroups)
}

func TestConvertToAPIUsersPage(t *testing.T) {
	var count = 10
	var input = kc.UsersPageRepresentation{Count: &count, Users: []kc.UserRepresentation{kc.UserRepresentation{}, kc.UserRepresentation{}}}
	var output = ConvertToAPIUsersPage(input)
	assert.Equal(t, count, *output.Count)
	assert.Equal(t, len(input.Users), len(output.Users))
}

func TestConvertToAPIUsersPageEmptySet(t *testing.T) {
	var input = kc.UsersPageRepresentation{Count: nil, Users: nil}
	var output = ConvertToAPIUsersPage(input)
	assert.NotNil(t, output.Users)
	assert.NotNil(t, output.Count)
	assert.Equal(t, 0, len(output.Users))
	assert.Equal(t, 0, *output.Count)

	var jsonRaw, _ = json.Marshal(output)
	var json = string(jsonRaw)
	assert.True(t, strings.Contains(json, `"users":[]`))
	assert.True(t, strings.Contains(json, `"count":0`))
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

func TestConvertToKCGroup(t *testing.T) {
	var group GroupRepresentation

	// Name
	var name = "a name"
	group.Name = &name
	assert.Equal(t, name, *ConvertToKCGroup(group).Name)
}

func TestConvertToDBAuthorizations(t *testing.T) {
	// Nil matrix authorizations
	{
		var apiAuthorizations = AuthorizationsRepresentation{}

		authorizations := ConvertToDBAuthorizations("realmID", "groupID", apiAuthorizations)
		assert.Equal(t, 0, len(authorizations))
	}

	// Empty matrix authorizations
	{
		var jsonMatrix = `{}`

		var matrix map[string]map[string]map[string]struct{}
		if err := json.Unmarshal([]byte(jsonMatrix), &matrix); err != nil {
			assert.Fail(t, "")
		}

		var apiAuthorizations = AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		authorizations := ConvertToDBAuthorizations("realmID", "groupID", apiAuthorizations)
		assert.Equal(t, 0, len(authorizations))
	}

	// Valid matrix authorizations
	{
		var jsonMatrix = `{
			"Action1": {},
			"Action2": {"*": {} },
			"Action3": {"*": {"*": {} }}, 
			"Action4": {"realm1": {} },
			"Action5": {"realm1": {"groupName1": {} }},
			"Action6": {"realm1": {"groupName1": {}, "groupName2": {}}},
			"Action7": {"realm1": {}, "realm2": {}},
			"Action8": {"realm1": {"groupName1": {} }, "realm2": {"groupName1": {} }},
			"Action9": {"realm1": {"groupName1": {}, "groupName2": {}}, "realm2": {"groupName1": {}, "groupName2": {}}}
		}`

		var matrix map[string]map[string]map[string]struct{}
		if err := json.Unmarshal([]byte(jsonMatrix), &matrix); err != nil {
			assert.Fail(t, "")
		}

		var apiAuthorizations = AuthorizationsRepresentation{
			Matrix: &matrix,
		}

		authorizations := ConvertToDBAuthorizations("realmID", "groupID", apiAuthorizations)
		assert.Equal(t, 15, len(authorizations))
	}
}

func TestConvertToAPIAuthorizations(t *testing.T) {
	var master = "master"
	var groupName1 = "groupName1"
	var groupName2 = "groupName2"
	var action = "action"
	var action2 = "action2"
	var any = "*"

	var authorizations = []configuration.Authorization{}

	var authz1 = configuration.Authorization{
		RealmID:   &master,
		GroupName: &groupName2,
		Action:    &action2,
	}

	var authz2 = configuration.Authorization{
		RealmID:       &master,
		GroupName:     &groupName2,
		Action:        &action2,
		TargetRealmID: &any,
	}

	var authz3 = configuration.Authorization{
		RealmID:         &master,
		GroupName:       &groupName1,
		Action:          &action,
		TargetRealmID:   &master,
		TargetGroupName: &groupName1,
	}

	authorizations = append(authorizations, authz1)
	authorizations = append(authorizations, authz2)
	authorizations = append(authorizations, authz3)

	var apiAuthorizations = ConvertToAPIAuthorizations(authorizations)
	var matrix = *apiAuthorizations.Matrix

	_, ok := matrix[action][master][groupName1]
	assert.Equal(t, true, ok)

	_, ok = matrix[action][master][master]
	assert.Equal(t, false, ok)

	_, ok = matrix[action2][any]
	assert.Equal(t, true, ok)
}

func TestConvertRequiredAction(t *testing.T) {
	var raKc kc.RequiredActionProviderRepresentation
	var alias = "alias"
	var name = "name"
	var boolTrue = true

	raKc.Alias = &alias
	raKc.Name = &name
	raKc.DefaultAction = &boolTrue

	assert.Equal(t, raKc.Alias, ConvertRequiredAction(&raKc).Alias)
	assert.Equal(t, raKc.Name, ConvertRequiredAction(&raKc).Name)
	assert.Equal(t, raKc.DefaultAction, ConvertRequiredAction(&raKc).DefaultAction)
}

func TestFederatedIdentityRepresentation(t *testing.T) {
	var userID = "id"
	var username = "uname"
	var fir = FederatedIdentityRepresentation{UserID: &userID, Username: &username}

	t.Run("ConvertToKCFedID", func(t *testing.T) {
		var res = ConvertToKCFedID(fir)
		assert.Equal(t, userID, *res.UserId)
		assert.Equal(t, username, *res.UserName)
	})

	t.Run("Validate - fails", func(t *testing.T) {
		assert.NotNil(t, fir.Validate())
	})
	t.Run("Validate - success", func(t *testing.T) {
		var uid = "abcdefgh-1234-1234-1234-1234abcd5678"
		fir.UserID = &uid
		assert.Nil(t, fir.Validate())
	})
}

func TestConvertRealmAdminConfiguration(t *testing.T) {
	t.Run("Empty struct", func(t *testing.T) {
		var config = configuration.RealmAdminConfiguration{}
		var res = ConvertRealmAdminConfigurationFromDBStruct(config)
		assert.Nil(t, res.Mode)
		assert.Len(t, res.AvailableChecks, 0)
		assert.Len(t, res.Accreditations, 0)
		assert.Equal(t, config, res.ConvertToDBStruct())
	})
	t.Run("Empty struct", func(t *testing.T) {
		var mode = "mode"
		var typeValue = "type"
		var condition = "condition"
		var validity = "2y"
		var accred = configuration.RealmAdminAccreditation{
			Type:      &typeValue,
			Condition: &condition,
			Validity:  &validity,
		}
		var config = configuration.RealmAdminConfiguration{
			Mode:            &mode,
			AvailableChecks: map[string]bool{"true": true, "false": false},
			Accreditations:  []configuration.RealmAdminAccreditation{accred},
		}
		var res = ConvertRealmAdminConfigurationFromDBStruct(config)
		assert.Equal(t, mode, *res.Mode)
		assert.Len(t, res.AvailableChecks, 2)
		assert.True(t, res.AvailableChecks["true"])
		assert.False(t, res.AvailableChecks["false"])
		assert.Len(t, res.Accreditations, 1)
		assert.Equal(t, typeValue, *res.Accreditations[0].Type)
		assert.Equal(t, condition, *res.Accreditations[0].Condition)
		assert.Equal(t, validity, *res.Accreditations[0].Validity)
		assert.Equal(t, config, res.ConvertToDBStruct())
	})
}

func TestNewBackOfficeConfigurationFromJSON(t *testing.T) {
	t.Run("Invalid JSON", func(t *testing.T) {
		var _, err = NewBackOfficeConfigurationFromJSON(`{"shop":{"shelves":{"articles":{"books": [1, 2, 3], "chairs": [4, 5, 6]}}}}`)
		assert.NotNil(t, err)
	})
	t.Run("Valid JSON", func(t *testing.T) {
		var boConf, err = NewBackOfficeConfigurationFromJSON(`
			{
				"realm1": {
					"customers": [ "group1", "group2", "group4" ],
					"teams": [ "group1", "group3" ]
				}
			}
		`)
		assert.Nil(t, err)
		assert.Len(t, boConf["realm1"], 2)
		assert.Len(t, boConf["realm1"]["customers"], 3)
		assert.Len(t, boConf["realm1"]["teams"], 2)
	})
	t.Run("Inalid configuration", func(t *testing.T) {
		var _, err = NewBackOfficeConfigurationFromJSON(`
			{
				"not-a-valid-value": {
					"my-realm": []
				}
			}
		`)
		assert.NotNil(t, err)
	})
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
	label := ""
	gender := "Male"
	birthDate := "1990-13-28"
	locale := "english"
	groups := []string{"f467ed7c", "7767ed7c-0a1d-4eee-9bb8-669c6f89c007"}
	roles := []string{"abcded7", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}
	empty := ""

	var users []UserRepresentation
	for i := 0; i < 12; i++ {
		users = append(users, createValidUserRepresentation())
	}

	users[0].ID = &id
	users[1].Username = &username
	users[2].Email = &email
	users[3].PhoneNumber = &phoneNumber
	users[4].Label = &label
	users[5].Gender = &gender
	users[6].BirthDate = &birthDate
	users[7].Groups = &groups
	users[8].Roles = &roles
	users[9].Locale = &locale
	users[10].FirstName = &empty
	users[11].LastName = &empty

	for idx, user := range users {
		assert.NotNil(t, user.Validate(), "Check is expected to be invalid. Test #%d failed", idx)
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

	roles[0].ID = &id
	roles[1].Name = &name
	roles[2].Description = &description
	roles[3].ContainerID = &id

	for _, role := range roles {
		assert.NotNil(t, role.Validate())
	}
}

func TestValidateGroupRepresentation(t *testing.T) {
	{
		group := createValidGroupRepresentation()
		assert.Nil(t, group.Validate())
	}

	id := "f467ed7c"
	name := "name *"

	var groups []GroupRepresentation
	for i := 0; i < 2; i++ {
		groups = append(groups, createValidGroupRepresentation())
	}

	groups[0].ID = &id
	groups[1].Name = &name

	for _, group := range groups {
		assert.NotNil(t, group.Validate())
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

	defaultClientID := "something$invalid"
	defaultRedirectURI := "ht//tp://company.com"

	var configs []RealmCustomConfiguration
	for i := 0; i < 2; i++ {
		configs = append(configs, createValidRealmCustomConfiguration())
	}

	configs[0].DefaultClientID = &defaultClientID
	configs[1].DefaultRedirectURI = &defaultRedirectURI

	for _, config := range configs {
		assert.NotNil(t, config.Validate())
	}
}

func createValidRealmAdminConfiguration() RealmAdminConfiguration {
	var trustID = "trustID"
	var value = "value"
	var validity = "2y4m"
	var condition = "IDNow"
	var accred = RealmAdminAccreditation{Type: &value, Validity: &validity, Condition: &condition}
	return RealmAdminConfiguration{
		Mode:            &trustID,
		AvailableChecks: map[string]bool{"IDNow": false, "physical-check": true},
		Accreditations:  []RealmAdminAccreditation{accred},
	}
}

func TestValidateRealmAdminConfiguration(t *testing.T) {
	t.Run("Valid default configuration", func(t *testing.T) {
		var conf = CreateDefaultRealmAdminConfiguration()
		assert.Nil(t, conf.Validate())
	})
	t.Run("Valid configuration", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		assert.Nil(t, realmAdminConf.Validate())
	})
	t.Run("Missing mode", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.Mode = nil
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid mode", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		var invalid = "invalid"
		realmAdminConf.Mode = &invalid
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid available checks", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.AvailableChecks["invalid-key"] = false
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid accreditation validity", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		var invalid = "2y4"
		realmAdminConf.Accreditations[0].Validity = &invalid
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid accreditation condition", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		var invalid = "invalid-key"
		realmAdminConf.Accreditations[0].Condition = &invalid
		assert.NotNil(t, realmAdminConf.Validate())
	})
}

func TestValidateRequiredAction(t *testing.T) {
	t.Run("Valid required action", func(t *testing.T) {
		action := createValidRequiredAction()
		assert.Nil(t, action.Validate())
	})
	t.Run("Invalid required action", func(t *testing.T) {
		action := RequiredAction("^")
		assert.NotNil(t, action.Validate())
	})
	t.Run("Empty required action", func(t *testing.T) {
		action := RequiredAction("")
		assert.Nil(t, action.Validate())
	})
}

func TestValidateFederatedIdentityRepresentation(t *testing.T) {
	var userID = "abcd1234-abcd-1234-efgh-abcd1234efgh"
	var username = "abcdef"
	var invalid = "invalid"
	var fi FederatedIdentityRepresentation

	fi.UserID = &userID
	fi.Username = &username
	assert.Nil(t, fi.Validate())

	fi.UserID = &invalid
	fi.Username = &username
	assert.NotNil(t, fi.Validate())

	fi.UserID = &userID
	fi.Username = nil
	assert.NotNil(t, fi.Validate())
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
	user.ID = &id
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
	role.ID = &id
	role.Name = &name
	role.Description = &description
	role.ContainerID = &id
	role.ClientRole = &boolTrue
	role.Composite = &boolTrue

	return role
}

func createValidGroupRepresentation() GroupRepresentation {
	id := "f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee"
	name := "name"

	var group = GroupRepresentation{}
	group.ID = &id
	group.Name = &name

	return group
}

func createValidPasswordRepresentation() PasswordRepresentation {
	password := "password"

	return PasswordRepresentation{
		Value: &password,
	}
}

func createValidRealmCustomConfiguration() RealmCustomConfiguration {
	defaultClientID := "backofficeid"
	defaultRedirectURI := "http://company.com"

	return RealmCustomConfiguration{
		DefaultClientID:    &defaultClientID,
		DefaultRedirectURI: &defaultRedirectURI,
	}
}

func createValidRequiredAction() RequiredAction {
	return RequiredAction("verify-email")
}
