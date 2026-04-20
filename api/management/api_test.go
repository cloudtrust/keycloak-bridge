package apimanagement

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient"

	"github.com/cloudtrust/common-service/v2/configuration"
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

func TestConvertAttackDetectionStatus(t *testing.T) {
	t.Run("missing keys", func(t *testing.T) {
		var status = map[string]any{}
		assert.Equal(t, AttackDetectionStatusRepresentation{}, ConvertAttackDetectionStatus(status))
	})
	t.Run("nil values", func(t *testing.T) {
		var status = map[string]any{"numFailures": nil, "disabled": nil, "lastIPFailure": nil, "lastFailure": nil}
		var res = ConvertAttackDetectionStatus(status)
		assert.Nil(t, res.NumFailures)
		assert.Nil(t, res.Disabled)
		assert.Nil(t, res.LastIPFailure)
		assert.Nil(t, res.LastFailure)
	})
	t.Run("success", func(t *testing.T) {
		var status = map[string]any{"numFailures": "57", "disabled": "true", "lastIPFailure": "127.0.0.1", "lastFailure": "7"}
		var res = ConvertAttackDetectionStatus(status)
		assert.Equal(t, int64(57), *res.NumFailures)
		assert.True(t, *res.Disabled)
		assert.Equal(t, "127.0.0.1", *res.LastIPFailure)
		assert.Equal(t, int64(7), *res.LastFailure)
	})
}

func TestConvertToAPIUser(t *testing.T) {
	var ctx = context.TODO()
	var logger = log.NewNopLogger()
	profile := kc.UserProfileRepresentation{}

	var kcUser kc.UserRepresentation
	m := make(kc.Attributes)

	t.Run("Phone number", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).PhoneNumber)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbPhoneNumber, "+4122555555")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).PhoneNumber)
	})
	t.Run("Label", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Label)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbLabel, "a label")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Label)
	})
	t.Run("Gender", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Gender)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbGender, "a gender")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Gender)
	})
	t.Run("Birthdate", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).BirthDate)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbBirthDate, "25/12/0")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).BirthDate)
	})
	t.Run("Phone number verified", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).PhoneNumberVerified)
		kcUser.Attributes = &m
		m.SetBool(constants.AttrbPhoneNumberVerified, true)
		assert.True(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).PhoneNumberVerified)
	})
	t.Run("Locale", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Locale)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbLocale, "en")
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).Locale)
	})
	t.Run("SMS sent", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).SmsSent)
		kcUser.Attributes = &m
		m.SetInt(constants.AttrbSmsSent, 0)
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).SmsSent)
	})
	t.Run("SMS failed attempts", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).SmsAttempts)
		kcUser.Attributes = &m
		m.SetInt(constants.AttrbSmsAttempts, 0)
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).SmsAttempts)
	})
	t.Run("trustID groups", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).TrustIDGroups)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbTrustIDGroups, "en")
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).TrustIDGroups)
	})
	t.Run("Accreditations", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Accreditations)
		kcUser.SetAttribute("accreditations", []string{`{"type":"one", "creationMillis":1643380967867, "expiryDate":"05.04.2020"}`, `{"type":"two", "creationMillis":1643380967867, "expiryDate":"05.03.2022"}`, `{`})
		assert.Len(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).Accreditations, 2)
		kcUser.SetAttribute("accreditations", []string{``})
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Accreditations)
	})
	t.Run("Onboarding completed", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, profile, logger).OnboardingCompleted)
		kcUser.SetAttributeBool("onboardingCompleted", true)
		assert.True(t, *ConvertToAPIUser(ctx, kcUser, profile, logger).OnboardingCompleted)
	})
	t.Run("Dynamic attributes", func(t *testing.T) {
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

		assert.Len(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Dynamic, 0)
		kcUser.Attributes = &m
		m.SetString(kc.AttributeKey(customAttribute), "customValue")
		assert.Len(t, ConvertToAPIUser(ctx, kcUser, profile, logger).Dynamic, 1)
	})
}

func TestConvertToAPIUsersPage(t *testing.T) {
	var ctx = context.TODO()
	var logger = log.NewNopLogger()
	profile := kc.UserProfileRepresentation{}

	t.Run("With content", func(t *testing.T) {
		var count = 10
		var input = kc.UsersPageRepresentation{Count: &count, Users: []kc.UserRepresentation{{}, {}}}
		var output = ConvertToAPIUsersPage(ctx, input, profile, logger)
		assert.Equal(t, count, *output.Count)
		assert.Equal(t, len(input.Users), len(output.Users))
	})

	t.Run("Empty set", func(t *testing.T) {
		var input = kc.UsersPageRepresentation{Count: nil, Users: nil}
		var output = ConvertToAPIUsersPage(ctx, input, profile, logger)
		assert.NotNil(t, output.Users)
		assert.NotNil(t, output.Count)
		assert.Equal(t, 0, len(output.Users))
		assert.Equal(t, 0, *output.Count)

		var jsonRaw, _ = json.Marshal(output)
		var json = string(jsonRaw)
		assert.True(t, strings.Contains(json, `"users":[]`))
		assert.True(t, strings.Contains(json, `"count":0`))
	})
}

func TestConvertToKCUser(t *testing.T) {
	var user UserRepresentation
	profile := kc.UserProfileRepresentation{}

	t.Run("Phone number", func(t *testing.T) {
		assert.Nil(t, ConvertToKCUser(user, profile).Attributes)
		var phoneNumber = "+4122555555"
		user.PhoneNumber = &phoneNumber
		assert.Equal(t, phoneNumber, (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbPhoneNumber][0])
	})
	t.Run("Label", func(t *testing.T) {
		var label = "a label"
		user.Label = &label
		assert.Equal(t, label, (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbLabel][0])
	})
	t.Run("Gender", func(t *testing.T) {
		var gender = "a gender"
		user.Gender = &gender
		assert.Equal(t, gender, (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbGender][0])
	})
	t.Run("Birthdate", func(t *testing.T) {
		var date = "25/12/0"
		user.BirthDate = &date
		assert.Equal(t, date, (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbBirthDate][0])
	})
	t.Run("PhoneNumberVerified", func(t *testing.T) {
		var verified = true
		user.PhoneNumberVerified = &verified
		assert.Equal(t, "true", (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbPhoneNumberVerified][0])
	})
	t.Run("Locale", func(t *testing.T) {
		var locale = "it"
		user.Locale = &locale
		assert.Equal(t, locale, (*ConvertToKCUser(user, profile).Attributes)[constants.AttrbLocale][0])
	})
	t.Run("Dynamic attribute", func(t *testing.T) {
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

		value := "customValue"
		user.Dynamic = map[string]any{customAttribute: value}
		kcUser := ConvertToKCUser(user, profile)
		assert.Equal(t, value, kcUser.GetDynamicAttributes(profile)[customAttribute])
	})
}

func TestMergeUpdatableUser(t *testing.T) {
	var user UpdatableUserRepresentation
	var kcUser kc.UserRepresentation
	profile := kc.UserProfileRepresentation{}

	MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
	assert.Nil(t, kcUser.Attributes)

	t.Run("Label", func(t *testing.T) {
		var label = "a label"
		user.Label = &label
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, label, (*kcUser.Attributes)[constants.AttrbLabel][0])
	})

	t.Run("Gender", func(t *testing.T) {
		var gender = "a gender"
		user.Gender = &gender
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, gender, (*kcUser.Attributes)[constants.AttrbGender][0])
	})

	t.Run("Birthdate", func(t *testing.T) {
		var date = "25/12/0"
		user.BirthDate = &date
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, date, (*kcUser.Attributes)[constants.AttrbBirthDate][0])
	})

	t.Run("PhoneNumberVerified", func(t *testing.T) {
		var verified = true
		user.PhoneNumberVerified = &verified
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, "true", (*kcUser.Attributes)[constants.AttrbPhoneNumberVerified][0])
	})

	t.Run("Locale", func(t *testing.T) {
		var locale = "it"
		user.Locale = &locale
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, locale, (*kcUser.Attributes)[constants.AttrbLocale][0])
	})

	t.Run("Business ID", func(t *testing.T) {
		var businessID = "123456789"
		user.BusinessID = csjson.StringToOptional(businessID)
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user, profile)
		assert.Equal(t, businessID, *kcUser.Attributes.GetString(constants.AttrbBusinessID))
	})
}

func TestMarshalUserRepresentation(t *testing.T) {
	userJSON := `{"id":"251d6e49-7b91-4677-889d-8e43a093bdf3","username":"50000003","gender":"M","firstName":"Jordan","lastName":"Peele","email":"testtrustid+jordan+peele@gmail.com","emailVerified":true,"phoneNumber":"+41780000000","phoneNumberVerified":true,"birthDate":"25.10.1978","birthLocation":"Haddonfield NJ","nationality":"CH","idDocumentType":"ID_CARD","idDocumentNumber":"A1234567","idDocumentExpiration":"20.06.2033","idDocumentCountry":"CH","locale":"en","smsSent":0,"smsAttempts":0,"enabled":true,"accreditations":[{"type":"DEP","expiryDate":"11.07.2029","revoked":false,"expired":false}],"onboardingCompleted":true,"createdTimestamp":1746715933372,"dynamicAttribute":"custom"}`

	user := UserRepresentation{
		ID:                   new("251d6e49-7b91-4677-889d-8e43a093bdf3"),
		Username:             new("50000003"),
		Gender:               new("M"),
		FirstName:            new("Jordan"),
		LastName:             new("Peele"),
		Email:                new("testtrustid+jordan+peele@gmail.com"),
		EmailVerified:        new(true),
		PhoneNumber:          new("+41780000000"),
		PhoneNumberVerified:  new(true),
		BirthDate:            new("25.10.1978"),
		BirthLocation:        new("Haddonfield NJ"),
		Nationality:          new("CH"),
		IDDocumentType:       new("ID_CARD"),
		IDDocumentNumber:     new("A1234567"),
		IDDocumentExpiration: new("20.06.2033"),
		IDDocumentCountry:    new("CH"),
		Locale:               new("en"),
		SmsSent:              new(0),
		SmsAttempts:          new(0),
		Enabled:              new(true),
		Accreditations: &[]AccreditationRepresentation{
			{
				Type:       new("DEP"),
				ExpiryDate: new("11.07.2029"),
				Revoked:    new(false),
				Expired:    new(false),
			},
		},
		OnboardingCompleted: new(true),
		CreatedTimestamp:    new(int64(1746715933372)),
		Dynamic: map[string]any{
			"dynamicAttribute": "custom",
		},
	}

	var u UserRepresentation

	assert.Nil(t, json.Unmarshal([]byte(userJSON), &u))
	assert.Equal(t, user, u)

	valueJSON, err := json.Marshal(user)
	assert.Nil(t, err)
	pointerJSON, err := json.Marshal(&user)
	assert.Nil(t, err)

	var userFromValue UserRepresentation
	var userFromPointer UserRepresentation
	assert.Nil(t, json.Unmarshal(valueJSON, &userFromValue))
	assert.Nil(t, json.Unmarshal(pointerJSON, &userFromPointer))
	assert.Equal(t, user, userFromValue)
	assert.Equal(t, userFromValue, userFromPointer)
}

func TestConvertAPIRole(t *testing.T) {
	f := false
	containerID := "container-id"
	description := "description"
	id := "dfjlkfd-1224324"
	name := "name"
	kcRole := kc.RoleRepresentation{
		ClientRole:  &f,
		Composite:   &f,
		ContainerID: &containerID,
		Description: &description,
		ID:          &id,
		Name:        &name,
	}

	apiRole := ConvertToAPIRole(kcRole)

	assert.Equal(t, f, *apiRole.ClientRole)
	assert.Equal(t, f, *apiRole.Composite)
	assert.Equal(t, containerID, *apiRole.ContainerID)
	assert.Equal(t, id, *apiRole.ID)
	assert.Equal(t, name, *apiRole.Name)
}

func TestConvertToKCRole(t *testing.T) {
	f := false
	containerID := "container-id"
	description := "description"
	id := "dfjlkfd-1224324"
	name := "name"
	apiRole := RoleRepresentation{
		ClientRole:  &f,
		Composite:   &f,
		ContainerID: &containerID,
		Description: &description,
		ID:          &id,
		Name:        &name,
	}

	kcRole := ConvertToKCRole(apiRole)

	assert.Equal(t, f, *kcRole.ClientRole)
	assert.Equal(t, f, *kcRole.Composite)
	assert.Equal(t, containerID, *kcRole.ContainerID)
	assert.Equal(t, id, *kcRole.ID)
	assert.Equal(t, name, *kcRole.Name)
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
	var boolTrue = true

	raKc.Alias = new("alias")
	raKc.Name = new("name")
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
		assert.Equal(t, userID, *res.UserID)
		assert.Equal(t, username, *res.UserName)
	})

	t.Run("Validate - success", func(t *testing.T) {
		assert.Nil(t, fir.Validate())
	})
	t.Run("Validate - success", func(t *testing.T) {
		var uid = "abcdefgh-1234-1234-1234-1234abcd5678"
		fir.UserID = &uid
		assert.Nil(t, fir.Validate())
	})
	t.Run("Validate - user with email success", func(t *testing.T) {
		email := "toto@test.com"
		fedID := FederatedIdentityRepresentation{UserID: &email, Username: &email}
		assert.Nil(t, fedID.Validate())
	})
}

func TestConvertToAPIIdentityProvider(t *testing.T) {
	kcIdp := kc.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  new(false),
		Alias:                     new("testIDP"),
		AuthenticateByDefault:     new(false),
		Config:                    map[string]string{},
		DisplayName:               new("TEST"),
		Enabled:                   new(false),
		FirstBrokerLoginFlowAlias: new("first broker login"),
		HideOnLogin:               new(true),
		InternalID:                new("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  new(false),
		PostBrokerLoginFlowAlias:  new("post broker login"),
		ProviderID:                new("oidc"),
		StoreToken:                new(false),
		TrustEmail:                new(false),
	}
	res := ConvertToAPIIdentityProvider(kcIdp)
	assert.Equal(t, kcIdp.AddReadTokenRoleOnCreate, res.AddReadTokenRoleOnCreate)
	assert.Equal(t, kcIdp.Alias, res.Alias)
	assert.Equal(t, kcIdp.AuthenticateByDefault, res.AuthenticateByDefault)
	assert.Equal(t, kcIdp.Config, res.Config)
	assert.Equal(t, kcIdp.DisplayName, res.DisplayName)
	assert.Equal(t, kcIdp.Enabled, res.Enabled)
	assert.Equal(t, kcIdp.HideOnLogin, res.HideOnLogin)
	assert.Equal(t, kcIdp.InternalID, res.InternalID)
	assert.Equal(t, kcIdp.LinkOnly, res.LinkOnly)
	assert.Equal(t, kcIdp.PostBrokerLoginFlowAlias, res.PostBrokerLoginFlowAlias)
	assert.Equal(t, kcIdp.ProviderID, res.ProviderID)
	assert.Equal(t, kcIdp.StoreToken, res.StoreToken)
	assert.Equal(t, kcIdp.TrustEmail, res.TrustEmail)
}

func TestConvertRealmCustomConfiguration(t *testing.T) {
	t.Run("Empty struct", func(t *testing.T) {
		var res = CreateDefaultRealmCustomConfiguration()
		assert.Nil(t, res.DefaultClientID)
		assert.Nil(t, res.DefaultRedirectURI)
		assert.False(t, *res.APISelfAuthenticatorDeletionEnabled)
		assert.False(t, *res.APISelfPasswordChangeEnabled)
		assert.False(t, *res.APISelfAccountEditingEnabled)
		assert.False(t, *res.APISelfAccountDeletionEnabled)
		assert.False(t, *res.APISelfIDPLinksManagementEnabled)
		assert.False(t, *res.APISelfInitialPasswordDefinitionAllowed)
		assert.False(t, *res.ShowAuthenticatorsTab)
		assert.False(t, *res.ShowPasswordTab)
		assert.False(t, *res.ShowProfileTab)
		assert.False(t, *res.ShowAccountDeletionButton)
		assert.False(t, *res.ShowIDPLinksTab)
		assert.Nil(t, res.SelfServiceDefaultTab)
		assert.Nil(t, res.RedirectCancelledRegistrationURL)
		assert.Nil(t, res.RedirectSuccessfulRegistrationURL)
		assert.Nil(t, res.OnboardingRedirectURI)
		assert.Nil(t, res.OnboardingClientID)
		assert.Len(t, res.SelfRegisterGroupNames, 0)
		assert.Nil(t, res.BarcodeType)
		assert.Len(t, res.AllowedBackURLs, 0)
		assert.False(t, *res.OnboardingUserEditingEnabled)
		assert.Nil(t, res.IdentificationURL)
	})
	t.Run("Non empty struct", func(t *testing.T) {
		var bTrue = true
		var groups = []string{"grp1", "grp2"}
		var config = configuration.RealmConfiguration{
			DefaultClientID:                   new("account"),
			DefaultRedirectURI:                new("redirect-uri"),
			APISelfAccountEditingEnabled:      &bTrue,
			RedirectCancelledRegistrationURL:  new("cancelled"),
			RedirectSuccessfulRegistrationURL: new("successful"),
			OnboardingRedirectURI:             new("onboarding"),
			OnboardingClientID:                new("client"),
			SelfRegisterGroupNames:            groups,
			BarcodeType:                       new("barcodetype"),
			AllowedBackURL:                    new("back-url"),
			OnboardingUserEditingEnabled:      &bTrue,
			IdentificationURL:                 new("identification-url"),
		}
		var res = ConvertRealmCustomConfigurationFromDBStruct(config)
		assert.Equal(t, config.DefaultClientID, res.DefaultClientID)
		assert.Equal(t, config.DefaultRedirectURI, res.DefaultRedirectURI)
		assert.True(t, *res.APISelfAccountEditingEnabled)
		assert.Equal(t, config.RedirectCancelledRegistrationURL, res.RedirectCancelledRegistrationURL)
		assert.Equal(t, config.RedirectSuccessfulRegistrationURL, res.RedirectSuccessfulRegistrationURL)
		assert.Equal(t, config.OnboardingRedirectURI, res.OnboardingRedirectURI)
		assert.Equal(t, config.OnboardingClientID, res.OnboardingClientID)
		assert.Len(t, res.SelfRegisterGroupNames, len(groups))
		assert.Equal(t, config.BarcodeType, res.BarcodeType)
		assert.Equal(t, *config.AllowedBackURL, res.AllowedBackURLs[0])
		assert.True(t, *res.OnboardingUserEditingEnabled)
		assert.Equal(t, config.IdentificationURL, res.IdentificationURL)
	})
}

func TestConvertRealmAdminConfiguration(t *testing.T) {
	t.Run("Empty struct", func(t *testing.T) {
		var config = configuration.RealmAdminConfiguration{}
		var res = ConvertRealmAdminConfigurationFromDBStruct(config)
		assert.Equal(t, "corporate", *res.Mode)
		assert.Len(t, res.AvailableChecks, 3)
		assert.False(t, *res.SelfRegisterEnabled)
		assert.Nil(t, res.BoTheme)
		assert.Nil(t, res.SseTheme)
		assert.Nil(t, res.RegisterTheme)
		assert.Nil(t, res.SignerTheme)
		assert.True(t, *res.NeedVerifiedContact)
		assert.True(t, *res.NeedVerifiedContactAuxiliary)
		assert.False(t, *res.ConsentRequiredSocial)
		assert.False(t, *res.ConsentRequiredCorporate)
		assert.False(t, *res.ConsentRequiredCorporateAuxiliary)
		assert.False(t, *res.VideoIdentificationVoucherEnabled)
		assert.False(t, *res.VideoIdentificationAccountingEnabled)
		assert.False(t, *res.VideoIdentificationPrepaymentRequired)
		assert.False(t, *res.AutoIdentificationVoucherEnabled)
		assert.False(t, *res.AutoIdentificationAccountingEnabled)
		assert.False(t, *res.AutoIdentificationPrepaymentRequired)
		assert.Equal(t, []string{}, res.VideoIdentificationAllowedRoles)
		assert.Equal(t, []string{}, res.AuxiliaryVideoIdentificationAllowedRoles)
		assert.Equal(t, []string{}, res.AutoIdentificationAllowedRoles)
		assert.Equal(t, []string{}, res.PhysicalIdentificationAllowedRoles)
		assert.Equal(t, []string{}, res.AuxiliaryVideoIdentificationAllowedRoles)
		assert.False(t, *res.OnboardingStatusEnabled)
		assert.False(t, *res.AutoGeneratedUsernameEnabled)
		assert.False(t, *res.AutoGeneratedUsernameToggleEnabled)
		assert.False(t, *res.BOExternalIDPManagementEnabled)
	})
	t.Run("Non-empty values", func(t *testing.T) {
		var mode = "mode"
		var config = configuration.RealmAdminConfiguration{
			Mode:                                           &mode,
			AvailableChecks:                                map[string]bool{"true": true, "false": false},
			SelfRegisterEnabled:                            new(true),
			BoTheme:                                        new("trustid1"),
			SseTheme:                                       new("trustid2"),
			RegisterTheme:                                  new("trustid3"),
			SignerTheme:                                    new("trustid4"),
			NeedVerifiedContact:                            new(false),
			NeedVerifiedContactAuxiliary:                   new(false),
			ConsentRequiredSocial:                          new(true),
			ConsentRequiredCorporate:                       new(false),
			ConsentRequiredCorporateAuxiliary:              new(false),
			AccreditationRenewalWindowDays:                 new(30),
			VideoIdentificationVoucherEnabled:              new(true),
			VideoIdentificationAccountingEnabled:           new(true),
			VideoIdentificationPrepaymentRequired:          new(true),
			AuxiliaryVideoIdentificationVoucherEnabled:     new(true),
			AuxiliaryVideoIdentificationAccountingEnabled:  new(true),
			AuxiliaryVideoIdentificationPrepaymentRequired: new(true),
			AutoIdentificationVoucherEnabled:               new(true),
			AutoIdentificationAccountingEnabled:            new(true),
			AutoIdentificationPrepaymentRequired:           new(true),
			VideoIdentificationAllowedRoles:                []string{"role1"},
			AuxiliaryVideoIdentificationAllowedRoles:       []string{"role2"},
			AutoIdentificationAllowedRoles:                 []string{"role3"},
			PhysicalIdentificationAllowedRoles:             []string{"role4"},
			AuxiliaryPhysicalIdentificationAllowedRoles:    []string{"role5"},
			OnboardingStatusEnabled:                        new(true),
			AutoGeneratedUsernameEnabled:                   new(true),
			AutoGeneratedUsernameToggleEnabled:             new(true),
			BOExternalIDPManagementEnabled:                 new(true),
			RegisterMode:                                   new("default"),
		}
		var res = ConvertRealmAdminConfigurationFromDBStruct(config)
		assert.Equal(t, mode, *res.Mode)
		assert.Len(t, res.AvailableChecks, 2)
		assert.True(t, res.AvailableChecks["true"])
		assert.False(t, res.AvailableChecks["false"])
		assert.Equal(t, config, res.ConvertToDBStruct())
		assert.True(t, *res.SelfRegisterEnabled)
		assert.Equal(t, config.BoTheme, res.BoTheme)
		assert.Equal(t, config.SseTheme, res.SseTheme)
		assert.Equal(t, config.RegisterTheme, res.RegisterTheme)
		assert.Equal(t, config.SignerTheme, res.SignerTheme)
		assert.False(t, *res.NeedVerifiedContact)
		assert.False(t, *res.NeedVerifiedContactAuxiliary)
		assert.True(t, *res.ConsentRequiredSocial)
		assert.False(t, *res.ConsentRequiredCorporate)
		assert.False(t, *res.ConsentRequiredCorporateAuxiliary)
		assert.True(t, *res.VideoIdentificationVoucherEnabled)
		assert.True(t, *res.VideoIdentificationAccountingEnabled)
		assert.True(t, *res.VideoIdentificationPrepaymentRequired)
		assert.True(t, *res.AutoIdentificationVoucherEnabled)
		assert.True(t, *res.AutoIdentificationAccountingEnabled)
		assert.True(t, *res.AutoIdentificationPrepaymentRequired)
		assert.Equal(t, []string{"role1"}, res.VideoIdentificationAllowedRoles)
		assert.Equal(t, []string{"role2"}, res.AuxiliaryVideoIdentificationAllowedRoles)
		assert.Equal(t, []string{"role3"}, res.AutoIdentificationAllowedRoles)
		assert.Equal(t, []string{"role4"}, res.PhysicalIdentificationAllowedRoles)
		assert.Equal(t, []string{"role5"}, res.AuxiliaryPhysicalIdentificationAllowedRoles)
		assert.True(t, *res.OnboardingStatusEnabled)
		assert.True(t, *res.AutoGeneratedUsernameEnabled)
		assert.True(t, *res.AutoGeneratedUsernameToggleEnabled)
		assert.True(t, *res.BOExternalIDPManagementEnabled)
	})
}

func createValidRealmAdminAccreditation() RealmAdminAccreditation {
	return RealmAdminAccreditation{
		Type:      nil,
		Validity:  new("3y"),
		Condition: new(configuration.CheckKeyIDNow),
	}
}

func TestValidateRealmAdminAccreditation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidRealmAdminAccreditation()
		assert.Nil(t, config.Validate())
	})

	var accreds []RealmAdminAccreditation
	for range 4 {
		accreds = append(accreds, createValidRealmAdminAccreditation())
	}

	accreds[0].Validity = nil
	accreds[1].Validity = new("9z")
	accreds[2].Condition = nil
	accreds[3].Condition = new("NotAValidValue")

	for idx, accred := range accreds {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, accred.Validate())
		})
	}
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
	t.Run("Invalid configuration", func(t *testing.T) {
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

type mockUserProfile struct {
	err error
}

func (mup *mockUserProfile) GetRealmUserProfile(ctx context.Context, realmName string) (kc.UserProfileRepresentation, error) {
	return kc.UserProfileRepresentation{}, mup.err
}

func TestValidateUserRepresentation(t *testing.T) {
	var (
		ctx   = context.TODO()
		realm = "the-realm"
		mup   = &mockUserProfile{err: nil}
	)

	t.Run("Valid user", func(t *testing.T) {
		user := createValidUserRepresentation()
		assert.Nil(t, user.Validate(ctx, mup, realm, true))
	})
	t.Run("Invalid groups", func(t *testing.T) {
		user := createValidUserRepresentation()
		user.Groups = &[]string{"inval1d", "7767ed7c-0a1d-4eee-9bb8-669c6f89c007"}
		assert.NotNil(t, user.Validate(ctx, mup, realm, true))
	})
	t.Run("Valid role", func(t *testing.T) {
		user := createValidUserRepresentation()
		user.Roles = &[]string{"inval1d", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}
		assert.NotNil(t, user.Validate(ctx, mup, realm, true))
	})
}

func TestGetSetUserField(t *testing.T) {
	for _, field := range []string{
		"username:12345678", "email:name@domain.ch", "firstName:firstname", "lastName:lastname", "ENC_gender:M", "phoneNumber:+41223145789",
		"ENC_birthDate:12.11.2010", "ENC_birthLocation:chezouam", "ENC_nationality:ch", "ENC_idDocumentType:PASSPORT", "ENC_idDocumentNumber:123-456-789",
		"ENC_idDocumentExpiration:01.01.2039", "ENC_idDocumentCountry:ch", "locale:fr", "businessID:456789",
	} {
		var parts = strings.Split(field, ":")
		testGetSetUserField(t, parts[0], parts[1])
	}
	var user = UserRepresentation{}
	assert.Nil(t, user.GetField("not-existing-field"))
}

func testGetSetUserField(t *testing.T, fieldName string, value any) {
	var user UserRepresentation
	t.Run("Field "+fieldName, func(t *testing.T) {
		assert.Nil(t, user.GetField(fieldName))
		user.SetField(fieldName, value)
		assert.Equal(t, value, *user.GetField(fieldName).(*string))
	})
}

func TestValidateUpdatableUserRepresentation(t *testing.T) {
	var (
		ctx   = context.TODO()
		realm = "the-realm"
		mup   = &mockUserProfile{err: nil}
	)

	t.Run("Valid user", func(t *testing.T) {
		user := createValidUpdatableUserRepresentation()
		assert.Nil(t, user.Validate(ctx, mup, realm))
	})
	t.Run("Valid role", func(t *testing.T) {
		user := createValidUpdatableUserRepresentation()
		user.Roles = &[]string{"inval1d", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}
		assert.NotNil(t, user.Validate(ctx, mup, realm))
	})
}

func TestGetSetUpdatableUserField(t *testing.T) {
	for _, field := range []string{
		"username:12345678", "email:name@domain.ch", "firstName:firstname", "lastName:lastname", "ENC_gender:M", "phoneNumber:+41223145789",
		"ENC_birthDate:12.11.2010", "ENC_birthLocation:chezouam", "ENC_nationality:ch", "ENC_idDocumentType:PASSPORT", "ENC_idDocumentNumber:123-456-789",
		"ENC_idDocumentExpiration:01.01.2039", "ENC_idDocumentCountry:ch", "locale:fr", "businessID:456789",
	} {
		var parts = strings.Split(field, ":")
		testGetSetUpdatableUserField(t, parts[0], parts[1])
	}
	var user = UpdatableUserRepresentation{}
	assert.Nil(t, user.GetField("not-existing-field"))
}

func testGetSetUpdatableUserField(t *testing.T, fieldName string, value any) {
	var user UpdatableUserRepresentation
	t.Run("Field "+fieldName, func(t *testing.T) {
		assert.Nil(t, user.GetField(fieldName))
		user.SetField(fieldName, value)
		assert.Equal(t, value, *user.GetField(fieldName).(*string))
	})
}

func TestValidateRoleRepresentation(t *testing.T) {
	{
		role := createValidRoleRepresentation()
		assert.Nil(t, role.Validate())
	}

	var roles []RoleRepresentation
	for range 4 {
		roles = append(roles, createValidRoleRepresentation())
	}

	var sixtyTwoCharsLong = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var tooLongDescription = strings.Join([]string{sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong}, "")

	roles[0].ID = new("f467ed7c")
	roles[1].Name = new("name *")
	roles[2].Description = &tooLongDescription
	roles[3].ContainerID = new("")

	for _, role := range roles {
		assert.NotNil(t, role.Validate())
	}
}

func TestValidateGroupRepresentation(t *testing.T) {
	{
		group := createValidGroupRepresentation()
		assert.Nil(t, group.Validate())
	}

	var groups []GroupRepresentation
	for range 2 {
		groups = append(groups, createValidGroupRepresentation())
	}

	groups[0].ID = new("f467ed7c")
	groups[1].Name = new("name *")

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
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidRealmCustomConfiguration()
		assert.Nil(t, config.Validate())
	})

	var configs []RealmCustomConfiguration
	for range 8 {
		configs = append(configs, createValidRealmCustomConfiguration())
	}

	configs[0].DefaultClientID = new("something$invalid")
	configs[1].DefaultRedirectURI = new("ht//tp://company.com")
	configs[2].SelfServiceDefaultTab = new("")                      // Can't be empty
	configs[3].SelfServiceDefaultTab = new("-abc-def")              // No heading dash
	configs[4].SelfServiceDefaultTab = new("abc--def")              // Two dash in a row
	configs[5].SelfServiceDefaultTab = new("abc-def-")              // No final dash
	configs[6].SelfServiceDefaultTab = new("abcdefghijabcdefghijx") // Too long
	configs[7].AllowedBackURLs = []string{"ht//tp://company.com"}

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func createValidRealmAdminConfiguration() RealmAdminConfiguration {
	return RealmAdminConfiguration{
		Mode:            new("trustID"),
		AvailableChecks: map[string]bool{"IDNow": false, "physical-check": true},
		BoTheme:         new("my-theme"),
		SseTheme:        new("my-theme"),
		RegisterTheme:   new("my-theme"),
		SignerTheme:     new("my-theme"),
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
	t.Run("Invalid BO theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.BoTheme = new("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid SSE theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.SseTheme = new("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid Register theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.RegisterTheme = new("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid Signer theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.SignerTheme = new("")
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
	var invalid = "uaflztdlunsfvfpcvadfvbmjatejsfpdvqvlnurpfgfkhzlzidrsigcloltqqrbxxdwuarxeorzxbxutzzieyqhzvpkjfiwuelxhwfkdxokqdqkorpwrhdhnfuryabzi2"
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

	boolTrue := true

	var user = UserRepresentation{}
	user.ID = new("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	user.Username = new("username")
	user.Email = new("username@company.com")
	user.Enabled = &boolTrue
	user.EmailVerified = &boolTrue
	user.PhoneNumber = new("+415174234")
	user.PhoneNumberVerified = &boolTrue
	user.FirstName = new("Firstname")
	user.LastName = new("Lastname")
	user.Label = new("label")
	user.Gender = new("F")
	user.BirthDate = new("1990-12-28")
	user.Groups = &groups
	user.Roles = &roles
	user.Locale = new("en")

	return user
}

func createValidUpdatableUserRepresentation() UpdatableUserRepresentation {
	var roles = []string{"abcded7c-0a1d-4eee-9bb8-669c6f89c0ee", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}

	boolTrue := true

	var user = UpdatableUserRepresentation{}
	user.ID = new("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	user.Username = new("username")
	user.Email = csjson.StringToOptional("username@company.com")
	user.Enabled = &boolTrue
	user.EmailVerified = &boolTrue
	user.PhoneNumber = csjson.StringToOptional("+415174234")
	user.PhoneNumberVerified = &boolTrue
	user.FirstName = new("Firstname")
	user.LastName = new("Lastname")
	user.Label = new("label")
	user.Gender = new("F")
	user.BirthDate = new("1990-12-28")
	user.Roles = &roles
	user.Locale = new("en")

	return user
}

func createValidRoleRepresentation() RoleRepresentation {
	boolTrue := true

	var role = RoleRepresentation{}
	role.ID = new("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	role.Name = new("name")
	role.Description = new("description")
	role.ContainerID = new("12345678-abcd-beef-feed-123456781234")
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
	AllowedBackURLs := []string{"*"}

	return RealmCustomConfiguration{
		DefaultClientID:    &defaultClientID,
		DefaultRedirectURI: &defaultRedirectURI,
		AllowedBackURLs:    AllowedBackURLs,
	}
}

func createValidRequiredAction() RequiredAction {
	return RequiredAction("verify-email")
}

func TestConvertToAPIUserChecks(t *testing.T) {
	assert.Len(t, ConvertToAPIUserChecks([]accreditationsclient.CheckRepresentation{}), 0)

	var check = accreditationsclient.CheckRepresentation{
		Operator:  new("operator"),
		DateTime:  nil,
		Status:    new("status"),
		Type:      new("type"),
		Nature:    new("nature"),
		ProofType: new("ZIP"),
		Comment:   new("comment"),
	}
	var checks = []accreditationsclient.CheckRepresentation{check, check, check}
	var converted = ConvertToAPIUserChecks(checks)
	assert.Len(t, converted, len(checks))

	var checkDate = "29.12.2019"
	var date, _ = time.Parse(constants.SupportedDateLayouts[0], checkDate)
	check.DateTime = &date
	checks = []accreditationsclient.CheckRepresentation{check, check}
	converted = ConvertToAPIUserChecks(checks)
	assert.Len(t, converted, len(checks))
	assert.Equal(t, checkDate, *converted[0].CheckDate)
}

func createValidRealmContextKey() RealmContextKeyRepresentation {
	return RealmContextKeyRepresentation{
		ID:                new("id"),
		Label:             new("label"),
		IdentitiesRealm:   new("identities-realm"),
		Config:            createValidContextKeyConfig(),
		IsRegisterDefault: new(false),
	}
}

func createValidContextKeyConfig() *CtxKeyConfigRepresentation {
	return &CtxKeyConfigRepresentation{
		IdentificationURI: new("http://host/path/to/identification"),
		Onboarding:        createValidContextKeyOnboarding(),
		Accreditation:     createValidContextKeyAccreditation(),
		AutoVoucher:       createValidContextKeyAutoVoucher(),
	}
}

func createValidContextKeyOnboarding() CtxKeyOnboardingRepresentation {
	return CtxKeyOnboardingRepresentation{
		ClientID:       new("onboardingid-client"),
		RedirectURI:    new("http://host/full/path"),
		IsRedirectMode: new(true),
	}
}

func createValidContextKeyAccreditation() CtxKeyAccreditationRepresentation {
	return CtxKeyAccreditationRepresentation{
		EmailThemeRealm: new("theme-realm"),
	}
}

func createValidContextKeyAutoVoucher() CtxKeyAutoVoucherRepresentation {
	return CtxKeyAutoVoucherRepresentation{
		ServiceType:            new("AUTO_IDENTIFICATION"),
		Validity:               new("3y"),
		AccreditationRequested: new("DEP"),
		BilledRealm:            new("billed-realm"),
	}
}

func TestValidateRealmContextKeyRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidRealmContextKey()
		assert.Nil(t, config.Validate())
	})

	var configs []RealmContextKeyRepresentation
	for range 6 {
		configs = append(configs, createValidRealmContextKey())
	}

	configs[0].ID = nil
	configs[1].Label = nil
	configs[2].Label = new("")
	configs[3].IdentitiesRealm = nil
	configs[4].IdentitiesRealm = new("")
	configs[5].Config = nil

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func TestContextKeyConvertions(t *testing.T) {
	var customerRealm = "customer-realm"

	t.Run("Default case", func(t *testing.T) {
		var initialValue = createValidRealmContextKey()
		var dtoConverted = ConvertToDBContextKeys([]RealmContextKeyRepresentation{initialValue}, customerRealm)
		assert.Equal(t, customerRealm, dtoConverted[0].CustomerRealm)
		var valueConvertedFromDTO = ConvertToAPIContextKeys(dtoConverted)[0]
		assert.Equal(t, initialValue, valueConvertedFromDTO)
	})
	t.Run("Config fields are nil", func(t *testing.T) {
		var config = ConvertToAPIContextKeyConfig(configuration.ContextKeyConfiguration{
			Onboarding:        &configuration.ContextKeyConfOnboarding{},
			IdentificationURI: nil,
			AutoVoucher:       &configuration.ContextKeyConfAutovoucher{},
			Accreditation:     &configuration.ContextKeyConfAccreditation{},
			IDNow:             &configuration.ContextKeyConfIDNow{},
		})
		assert.Nil(t, config.Accreditation.EmailThemeRealm)
		assert.Nil(t, config.AutoVoucher.ServiceType)
		assert.Nil(t, config.AutoVoucher.Validity)
		assert.Nil(t, config.AutoVoucher.AccreditationRequested)
		assert.Nil(t, config.AutoVoucher.BilledRealm)
		assert.Nil(t, config.IdentificationURI)
		assert.Nil(t, config.Onboarding.ClientID)
		assert.Nil(t, config.Onboarding.RedirectURI)
		assert.Nil(t, config.Onboarding.IsRedirectMode)
		assert.Nil(t, config.IDNow.DesktopRedirectURI)
	})

	t.Run("Config fields are nil empty config", func(t *testing.T) {
		var config = ConvertToAPIContextKeyConfig(configuration.ContextKeyConfiguration{})
		assert.Nil(t, config.Accreditation.EmailThemeRealm)
		assert.Nil(t, config.AutoVoucher.ServiceType)
		assert.Nil(t, config.AutoVoucher.Validity)
		assert.Nil(t, config.AutoVoucher.AccreditationRequested)
		assert.Nil(t, config.AutoVoucher.BilledRealm)
		assert.Nil(t, config.IdentificationURI)
		assert.Nil(t, config.Onboarding.ClientID)
		assert.Nil(t, config.Onboarding.RedirectURI)
		assert.Nil(t, config.Onboarding.IsRedirectMode)
		assert.Nil(t, config.IDNow.DesktopRedirectURI)
	})
}

func TestValidateRealmContextKeys(t *testing.T) {
	t.Run("Valid configuration slice", func(t *testing.T) {
		config := []RealmContextKeyRepresentation{createValidRealmContextKey()}
		assert.Nil(t, ValidateRealmContextKeys(config, true))
		assert.Nil(t, ValidateRealmContextKeys(config, false))
		config[0].Label = nil
		assert.NotNil(t, ValidateRealmContextKeys(config, true))
		assert.NotNil(t, ValidateRealmContextKeys(config, false))
	})
	t.Run("Valid empty configuration slice", func(t *testing.T) {
		config := []RealmContextKeyRepresentation{}
		assert.Nil(t, ValidateRealmContextKeys(config, true))
		assert.NotNil(t, ValidateRealmContextKeys(config, false))
	})
	t.Run("Too many default context keys", func(t *testing.T) {
		config := []RealmContextKeyRepresentation{createValidRealmContextKey(), createValidRealmContextKey()}
		config[0].IsRegisterDefault = new(true)
		config[1].IsRegisterDefault = new(true)
		config[1].IdentitiesRealm = new("second-identities-realm")
		err := ValidateRealmContextKeys(config, true)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "toomany")
	})
	t.Run("Duplicated identities realm", func(t *testing.T) {
		config := []RealmContextKeyRepresentation{createValidRealmContextKey(), createValidRealmContextKey()}
		config[1].ID = new("second-id")
		err := ValidateRealmContextKeys(config, true)
		assert.Nil(t, err)
	})
}

func TestValidateCtxKeyConfigRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidRealmContextKey()
		assert.Nil(t, config.Validate())
	})

	var configs []RealmContextKeyRepresentation
	for range 5 {
		configs = append(configs, createValidRealmContextKey())
	}

	configs[0].Label = nil
	configs[1].Label = new("")
	configs[2].IdentitiesRealm = nil
	configs[3].IdentitiesRealm = new("")
	configs[4].Config = nil

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func TestValidateCtxKeyOnboardingRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidContextKeyOnboarding()
		assert.Nil(t, config.Validate())
	})

	var configs []CtxKeyOnboardingRepresentation
	for range 3 {
		configs = append(configs, createValidContextKeyOnboarding())
	}

	configs[0].ClientID = new("")
	configs[1].RedirectURI = new("")
	configs[2].RedirectURI = new("not.a.uri")

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func TestValidateCtxKeyAccreditationRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidContextKeyAccreditation()
		assert.Nil(t, config.Validate())
	})

	t.Run("Invalid case", func(t *testing.T) {
		config := CtxKeyAccreditationRepresentation{
			EmailThemeRealm: new(""),
		}
		assert.NotNil(t, config.Validate())
	})
}

func TestValidateCtxKeyAutoVoucherRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := createValidContextKeyAutoVoucher()
		assert.Nil(t, config.Validate())
	})

	var configs []CtxKeyAutoVoucherRepresentation
	for range 4 {
		configs = append(configs, createValidContextKeyAutoVoucher())
	}

	configs[0].ServiceType = new("")
	configs[1].Validity = new("")
	configs[2].AccreditationRequested = new("")
	configs[3].BilledRealm = new("")

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func TestValidateUpdatableThemeConfiguration(t *testing.T) {
	t.Run("Valid complete configuration", func(t *testing.T) {
		config := UpdatableThemeConfiguration{
			RealmName: new("realmName"),
			Settings: &ThemeConfigurationSettings{
				Color:      new("#FFFFFF"),
				MenuTheme:  new("light"),
				FontFamily: new("Lato"),
			},
			// mock assets at least 1KB long and starting with correct bytes
			Logo: func() []byte {
				b := make([]byte, 1024)
				b[0] = 0x89
				b[1] = 0x50
				return b
			}(),
			Favicon: func() []byte {
				b := make([]byte, 1024)
				b[0] = 0x3C
				b[1] = 0x73
				return b
			}(),
			Translations: map[string]any{
				"test": "test value",
				"test2": map[string]any{
					"subkey": "subvalue",
				},
			},
		}
		assert.Nil(t, config.Validate())
	})

	t.Run("valid minimal configurations", func(t *testing.T) {
		config := UpdatableThemeConfiguration{
			RealmName: new("realmName"),
			Settings:  &ThemeConfigurationSettings{},
		}
		assert.Nil(t, config.Validate())
	})

	t.Run("Invalid configurations", func(t *testing.T) {
		var configs []UpdatableThemeConfiguration
		for range 10 {
			configs = append(configs, UpdatableThemeConfiguration{
				RealmName: new("realmName"),
				Settings:  &ThemeConfigurationSettings{},
			})
		}

		configs[0].RealmName = nil
		configs[1].RealmName = new("")
		configs[2].Settings.Color = new("not-a-hex-color-code")
		configs[3].Settings.MenuTheme = new("not.a.valid.theme")        // not "light", "dark" or primary
		configs[4].Settings.FontFamily = new("not-a-valid-font-family") // not Lato or Roboto
		configs[5].Logo = []byte{0x89, 0x50}                            // too small
		configs[6].Logo = make([]byte, 1024)                            // not a png, jpeg or svg
		configs[7].Favicon = []byte{0x3C, 0x73}                         // too small
		configs[8].Favicon = func() []byte {
			b := make([]byte, 1024)
			b[0] = 0x89
			b[1] = 0x50
			return b
		}() // not an svg
		configs[9].Translations = map[string]any{
			"key": map[string]any{
				"subkey": 12345,
			},
		} // invalid type

		for idx, config := range configs {
			t.Run(fmt.Sprintf("Invalid case #%d", idx), func(t *testing.T) {
				assert.NotNil(t, config.Validate())
			})
		}
	})
}

func TestConvertToThemeConfiguration(t *testing.T) {
	t.Run("Empty struct", func(t *testing.T) {
		var config = configuration.ThemeConfiguration{}
		var res = ConvertToThemeConfiguration(config)
		assert.Nil(t, res.Settings)
		assert.Nil(t, res.Logo)
		assert.Nil(t, res.Favicon)
	})

	t.Run("Non-empty values", func(t *testing.T) {
		var config = configuration.ThemeConfiguration{
			Settings: &configuration.ThemeConfigurationSettings{
				Color:      new("#FFFFFF"),
				MenuTheme:  new("light"),
				FontFamily: new("Lato"),
			},
			Logo:    []byte{0x89, 0x50, 0x4E, 0x47},
			Favicon: []byte{0x3C, 0x73, 0x76, 0x67},
		}
		const expectedLogo = "data:image/png;base64,iVBORw=="
		const expectedFavicon = "data:image/svg+xml;base64,PHN2Zw=="
		var res = ConvertToThemeConfiguration(config)
		assert.NotNil(t, res.Settings)
		assert.Equal(t, config.Settings.Color, res.Settings.Color)
		assert.Equal(t, config.Settings.MenuTheme, res.Settings.MenuTheme)
		assert.Equal(t, config.Settings.FontFamily, res.Settings.FontFamily)
		assert.Equal(t, expectedLogo, *res.Logo)
		assert.Equal(t, expectedFavicon, *res.Favicon)
	})
}

func TestContextKeyIDNowConversions(t *testing.T) {
	idnowConfig := configuration.ContextKeyConfIDNow{
		DesktopRedirectURI: new("http://redirect.uri/after/idnow"),
	}

	apiConfig := ConvertToAPIContextKeyIDNow(&idnowConfig)
	assert.Equal(t, idnowConfig.DesktopRedirectURI, apiConfig.DesktopRedirectURI)

	dbConfig := apiConfig.ToDatabaseModel()
	assert.Equal(t, idnowConfig.DesktopRedirectURI, dbConfig.DesktopRedirectURI)
}

func TestValidateCtxKeyIDNowRepresentation(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := configuration.ContextKeyConfIDNow{
			DesktopRedirectURI: new("http://redirect.uri?theme=mytheme"),
		}
		apiConfig := ConvertToAPIContextKeyIDNow(&config)
		assert.Nil(t, apiConfig.Validate())
	})

	t.Run("Invalid configuration", func(t *testing.T) {
		config := configuration.ContextKeyConfIDNow{
			DesktopRedirectURI: new("not.a.valid.uri"),
		}
		apiConfig := ConvertToAPIContextKeyIDNow(&config)
		assert.NotNil(t, apiConfig.Validate())
	})
}
