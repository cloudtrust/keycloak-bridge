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

func ptr(value string) *string {
	return &value
}
func boolPtr(value bool) *bool {
	return &value
}

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
		var status = map[string]interface{}{}
		assert.Equal(t, AttackDetectionStatusRepresentation{}, ConvertAttackDetectionStatus(status))
	})
	t.Run("nil values", func(t *testing.T) {
		var status = map[string]interface{}{"numFailures": nil, "disabled": nil, "lastIPFailure": nil, "lastFailure": nil}
		var res = ConvertAttackDetectionStatus(status)
		assert.Nil(t, res.NumFailures)
		assert.Nil(t, res.Disabled)
		assert.Nil(t, res.LastIPFailure)
		assert.Nil(t, res.LastFailure)
	})
	t.Run("success", func(t *testing.T) {
		var status = map[string]interface{}{"numFailures": "57", "disabled": "true", "lastIPFailure": "127.0.0.1", "lastFailure": "7"}
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

	var kcUser kc.UserRepresentation
	m := make(kc.Attributes)

	t.Run("Phone number", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).PhoneNumber)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbPhoneNumber, "+4122555555")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, logger).PhoneNumber)
	})
	t.Run("Label", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).Label)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbLabel, "a label")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, logger).Label)
	})
	t.Run("Gender", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).Gender)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbGender, "a gender")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, logger).Gender)
	})
	t.Run("Birthdate", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).BirthDate)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbBirthDate, "25/12/0")
		assert.NotNil(t, ConvertToAPIUser(ctx, kcUser, logger).BirthDate)
	})
	t.Run("Phone number verified", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).PhoneNumberVerified)
		kcUser.Attributes = &m
		m.SetBool(constants.AttrbPhoneNumberVerified, true)
		assert.True(t, *ConvertToAPIUser(ctx, kcUser, logger).PhoneNumberVerified)
	})
	t.Run("Locale", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).Locale)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbLocale, "en")
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, logger).Locale)
	})
	t.Run("SMS sent", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).SmsSent)
		kcUser.Attributes = &m
		m.SetInt(constants.AttrbSmsSent, 0)
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, logger).SmsSent)
	})
	t.Run("SMS failed attempts", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).SmsAttempts)
		kcUser.Attributes = &m
		m.SetInt(constants.AttrbSmsAttempts, 0)
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, logger).SmsAttempts)
	})
	t.Run("trustID groups", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).TrustIDGroups)
		kcUser.Attributes = &m
		m.SetString(constants.AttrbTrustIDGroups, "en")
		assert.NotNil(t, *ConvertToAPIUser(ctx, kcUser, logger).TrustIDGroups)
	})
	t.Run("Accreditations", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).Accreditations)
		kcUser.SetAttribute("accreditations", []string{`{"type":"one", "creationMillis":1643380967867, "expiryDate":"05.04.2020"}`, `{"type":"two", "creationMillis":1643380967867, "expiryDate":"05.03.2022"}`, `{`})
		assert.Len(t, *ConvertToAPIUser(ctx, kcUser, logger).Accreditations, 2)
		kcUser.SetAttribute("accreditations", []string{``})
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).Accreditations)
	})
	t.Run("Onboarding completed", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUser(ctx, kcUser, logger).OnboardingCompleted)
		kcUser.SetAttributeBool("onboardingCompleted", true)
		assert.True(t, *ConvertToAPIUser(ctx, kcUser, logger).OnboardingCompleted)
	})
}

func TestConvertToAPIUsersPage(t *testing.T) {
	var ctx = context.TODO()
	var logger = log.NewNopLogger()

	t.Run("With content", func(t *testing.T) {
		var count = 10
		var input = kc.UsersPageRepresentation{Count: &count, Users: []kc.UserRepresentation{{}, {}}}
		var output = ConvertToAPIUsersPage(ctx, input, logger)
		assert.Equal(t, count, *output.Count)
		assert.Equal(t, len(input.Users), len(output.Users))
	})

	t.Run("Empty set", func(t *testing.T) {
		var input = kc.UsersPageRepresentation{Count: nil, Users: nil}
		var output = ConvertToAPIUsersPage(ctx, input, logger)
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

	// Phone number
	assert.Nil(t, ConvertToKCUser(user).Attributes)
	var phoneNumber = "+4122555555"
	user.PhoneNumber = &phoneNumber
	assert.Equal(t, phoneNumber, (*ConvertToKCUser(user).Attributes)[constants.AttrbPhoneNumber][0])

	// Label
	var label = "a label"
	user.Label = &label
	assert.Equal(t, label, (*ConvertToKCUser(user).Attributes)[constants.AttrbLabel][0])

	// Gender
	var gender = "a gender"
	user.Gender = &gender
	assert.Equal(t, gender, (*ConvertToKCUser(user).Attributes)[constants.AttrbGender][0])

	// Birthdate
	var date = "25/12/0"
	user.BirthDate = &date
	assert.Equal(t, date, (*ConvertToKCUser(user).Attributes)[constants.AttrbBirthDate][0])

	// PhoneNumberVerified
	var verified = true
	user.PhoneNumberVerified = &verified
	assert.Equal(t, "true", (*ConvertToKCUser(user).Attributes)[constants.AttrbPhoneNumberVerified][0])

	// Locale
	var locale = "it"
	user.Locale = &locale
	assert.Equal(t, locale, (*ConvertToKCUser(user).Attributes)[constants.AttrbLocale][0])

}

func TestMergeUpdatableUser(t *testing.T) {
	var user UpdatableUserRepresentation
	var kcUser kc.UserRepresentation

	MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
	assert.Nil(t, kcUser.Attributes)

	t.Run("Label", func(t *testing.T) {
		var label = "a label"
		user.Label = &label
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, label, (*kcUser.Attributes)[constants.AttrbLabel][0])
	})

	t.Run("Gender", func(t *testing.T) {
		var gender = "a gender"
		user.Gender = &gender
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, gender, (*kcUser.Attributes)[constants.AttrbGender][0])
	})

	t.Run("Birthdate", func(t *testing.T) {
		var date = "25/12/0"
		user.BirthDate = &date
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, date, (*kcUser.Attributes)[constants.AttrbBirthDate][0])
	})

	t.Run("PhoneNumberVerified", func(t *testing.T) {
		var verified = true
		user.PhoneNumberVerified = &verified
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, "true", (*kcUser.Attributes)[constants.AttrbPhoneNumberVerified][0])
	})

	t.Run("Locale", func(t *testing.T) {
		var locale = "it"
		user.Locale = &locale
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, locale, (*kcUser.Attributes)[constants.AttrbLocale][0])
	})

	t.Run("Business ID", func(t *testing.T) {
		var businessID = "123456789"
		user.BusinessID = csjson.StringToOptional(businessID)
		kcUser = kc.UserRepresentation{}
		MergeUpdatableUserWithoutEmailAndPhoneNumber(&kcUser, user)
		assert.Equal(t, businessID, *kcUser.Attributes.GetString(constants.AttrbBusinessID))
	})
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

	raKc.Alias = ptr("alias")
	raKc.Name = ptr("name")
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
		AddReadTokenRoleOnCreate:  boolPtr(false),
		Alias:                     ptr("testIDP"),
		AuthenticateByDefault:     boolPtr(false),
		Config:                    &map[string]interface{}{},
		DisplayName:               ptr("TEST"),
		Enabled:                   boolPtr(false),
		FirstBrokerLoginFlowAlias: ptr("first broker login"),
		InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  boolPtr(false),
		PostBrokerLoginFlowAlias:  ptr("post broker login"),
		ProviderID:                ptr("oidc"),
		StoreToken:                boolPtr(false),
		TrustEmail:                boolPtr(false),
	}
	res := ConvertToAPIIdentityProvider(kcIdp)
	assert.Equal(t, kcIdp.AddReadTokenRoleOnCreate, res.AddReadTokenRoleOnCreate)
	assert.Equal(t, kcIdp.Alias, res.Alias)
	assert.Equal(t, kcIdp.AuthenticateByDefault, res.AuthenticateByDefault)
	assert.Equal(t, kcIdp.Config, res.Config)
	assert.Equal(t, kcIdp.DisplayName, res.DisplayName)
	assert.Equal(t, kcIdp.Enabled, res.Enabled)
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
		assert.Len(t, *res.SelfRegisterGroupNames, 0)
		assert.Nil(t, res.BarcodeType)
		assert.Len(t, res.AllowedBackURLs, 0)
	})
	t.Run("Non empty struct", func(t *testing.T) {
		var bTrue = true
		var groups = []string{"grp1", "grp2"}
		var config = configuration.RealmConfiguration{
			DefaultClientID:                   ptr("account"),
			DefaultRedirectURI:                ptr("redirect-uri"),
			APISelfAccountEditingEnabled:      &bTrue,
			RedirectCancelledRegistrationURL:  ptr("cancelled"),
			RedirectSuccessfulRegistrationURL: ptr("successful"),
			OnboardingRedirectURI:             ptr("onboarding"),
			OnboardingClientID:                ptr("client"),
			SelfRegisterGroupNames:            &groups,
			BarcodeType:                       ptr("barcodetype"),
			AllowedBackURL:                    ptr("back-url"),
		}
		var res = ConvertRealmCustomConfigurationFromDBStruct(config)
		assert.Equal(t, config.DefaultClientID, res.DefaultClientID)
		assert.Equal(t, config.DefaultRedirectURI, res.DefaultRedirectURI)
		assert.True(t, *res.APISelfAccountEditingEnabled)
		assert.Equal(t, config.RedirectCancelledRegistrationURL, res.RedirectCancelledRegistrationURL)
		assert.Equal(t, config.RedirectSuccessfulRegistrationURL, res.RedirectSuccessfulRegistrationURL)
		assert.Equal(t, config.OnboardingRedirectURI, res.OnboardingRedirectURI)
		assert.Equal(t, config.OnboardingClientID, res.OnboardingClientID)
		assert.Len(t, *res.SelfRegisterGroupNames, len(groups))
		assert.Equal(t, config.BarcodeType, res.BarcodeType)
		assert.Equal(t, *config.AllowedBackURL, res.AllowedBackURLs[0])
	})
}

func TestConvertRealmAdminConfiguration(t *testing.T) {
	t.Run("Empty struct", func(t *testing.T) {
		var config = configuration.RealmAdminConfiguration{}
		var res = ConvertRealmAdminConfigurationFromDBStruct(config)
		assert.Equal(t, "corporate", *res.Mode)
		assert.Len(t, res.AvailableChecks, 3)
		assert.False(t, *res.SelfRegisterEnabled)
		assert.False(t, *res.ShowGlnEditing)
		assert.Nil(t, res.BoTheme)
		assert.Nil(t, res.SseTheme)
		assert.Nil(t, res.RegisterTheme)
		assert.Nil(t, res.SignerTheme)
		assert.False(t, *res.VideoIdentificationVoucherEnabled)
		assert.False(t, *res.VideoIdentificationAccountingEnabled)
		assert.False(t, *res.VideoIdentificationPrepaymentRequired)
		assert.False(t, *res.AutoIdentificationVoucherEnabled)
		assert.False(t, *res.AutoIdentificationAccountingEnabled)
		assert.False(t, *res.AutoIdentificationPrepaymentRequired)
		assert.False(t, *res.OnboardingStatusEnabled)
	})
	t.Run("Non-empty values", func(t *testing.T) {
		var mode = "mode"
		var selfRegisterEnabled = true
		var needVerifiedContact = false
		var consentRequiredSocial = true
		var consentRequiredCorporate = false
		var showGlnEditing = true
		var videoIdentificationVoucherEnabled = true
		var videoIdentificationAccountingEnabled = true
		var videoIdentificationPrepaymentRequired = true
		var autoIdentificationVoucherEnabled = true
		var autoIdentificationAccountingEnabled = true
		var autoIdentificationPrepaymentRequired = true
		var onBoardingStatusEnabled = true
		var config = configuration.RealmAdminConfiguration{
			Mode:                                  &mode,
			AvailableChecks:                       map[string]bool{"true": true, "false": false},
			SelfRegisterEnabled:                   &selfRegisterEnabled,
			BoTheme:                               ptr("trustid1"),
			SseTheme:                              ptr("trustid2"),
			RegisterTheme:                         ptr("trustid3"),
			SignerTheme:                           ptr("trustid4"),
			NeedVerifiedContact:                   &needVerifiedContact,
			ConsentRequiredSocial:                 &consentRequiredSocial,
			ConsentRequiredCorporate:              &consentRequiredCorporate,
			ShowGlnEditing:                        &showGlnEditing,
			VideoIdentificationVoucherEnabled:     &videoIdentificationVoucherEnabled,
			VideoIdentificationAccountingEnabled:  &videoIdentificationAccountingEnabled,
			VideoIdentificationPrepaymentRequired: &videoIdentificationPrepaymentRequired,
			AutoIdentificationVoucherEnabled:      &autoIdentificationVoucherEnabled,
			AutoIdentificationAccountingEnabled:   &autoIdentificationAccountingEnabled,
			AutoIdentificationPrepaymentRequired:  &autoIdentificationPrepaymentRequired,
			OnboardingStatusEnabled:               &onBoardingStatusEnabled,
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
		assert.True(t, *res.ConsentRequiredSocial)
		assert.True(t, *res.ShowGlnEditing)
		assert.True(t, *res.VideoIdentificationVoucherEnabled)
		assert.True(t, *res.VideoIdentificationAccountingEnabled)
		assert.True(t, *res.VideoIdentificationPrepaymentRequired)
		assert.True(t, *res.AutoIdentificationVoucherEnabled)
		assert.True(t, *res.AutoIdentificationAccountingEnabled)
		assert.True(t, *res.AutoIdentificationPrepaymentRequired)
		assert.True(t, *res.OnboardingStatusEnabled)
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

func testGetSetUserField(t *testing.T, fieldName string, value interface{}) {
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

func testGetSetUpdatableUserField(t *testing.T, fieldName string, value interface{}) {
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
	for i := 0; i < 4; i++ {
		roles = append(roles, createValidRoleRepresentation())
	}

	var sixtyTwoCharsLong = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var tooLongDescription = strings.Join([]string{sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong, sixtyTwoCharsLong}, "")

	roles[0].ID = ptr("f467ed7c")
	roles[1].Name = ptr("name *")
	roles[2].Description = &tooLongDescription
	roles[3].ContainerID = ptr("")

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
	for i := 0; i < 2; i++ {
		groups = append(groups, createValidGroupRepresentation())
	}

	groups[0].ID = ptr("f467ed7c")
	groups[1].Name = ptr("name *")

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
	for i := 0; i < 8; i++ {
		configs = append(configs, createValidRealmCustomConfiguration())
	}

	configs[0].DefaultClientID = ptr("something$invalid")
	configs[1].DefaultRedirectURI = ptr("ht//tp://company.com")
	configs[2].SelfServiceDefaultTab = ptr("")                      // Can't be empty
	configs[3].SelfServiceDefaultTab = ptr("-abc-def")              // No heading dash
	configs[4].SelfServiceDefaultTab = ptr("abc--def")              // Two dash in a row
	configs[5].SelfServiceDefaultTab = ptr("abc-def-")              // No final dash
	configs[6].SelfServiceDefaultTab = ptr("abcdefghijabcdefghijx") // Too long
	configs[7].AllowedBackURLs = []string{"ht//tp://company.com"}

	for idx, config := range configs {
		t.Run(fmt.Sprintf("Invalid case #%d", idx+1), func(t *testing.T) {
			assert.NotNil(t, config.Validate())
		})
	}
}

func createValidRealmAdminConfiguration() RealmAdminConfiguration {
	return RealmAdminConfiguration{
		Mode:            ptr("trustID"),
		AvailableChecks: map[string]bool{"IDNow": false, "physical-check": true},
		BoTheme:         ptr("my-theme"),
		SseTheme:        ptr("my-theme"),
		RegisterTheme:   ptr("my-theme"),
		SignerTheme:     ptr("my-theme"),
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
		realmAdminConf.BoTheme = ptr("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid SSE theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.SseTheme = ptr("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid Register theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.RegisterTheme = ptr("")
		assert.NotNil(t, realmAdminConf.Validate())
	})
	t.Run("Invalid Signer theme", func(t *testing.T) {
		var realmAdminConf = createValidRealmAdminConfiguration()
		realmAdminConf.SignerTheme = ptr("")
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
	user.ID = ptr("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	user.Username = ptr("username")
	user.Email = ptr("username@company.com")
	user.Enabled = &boolTrue
	user.EmailVerified = &boolTrue
	user.PhoneNumber = ptr("+415174234")
	user.PhoneNumberVerified = &boolTrue
	user.FirstName = ptr("Firstname")
	user.LastName = ptr("Lastname")
	user.Label = ptr("label")
	user.Gender = ptr("F")
	user.BirthDate = ptr("1990-12-28")
	user.Groups = &groups
	user.Roles = &roles
	user.Locale = ptr("en")

	return user
}

func createValidUpdatableUserRepresentation() UpdatableUserRepresentation {
	var roles = []string{"abcded7c-0a1d-4eee-9bb8-669c6f89c0ee", "7767ed7c-0a1d-4eee-9bb8-669c6f898888"}

	boolTrue := true

	var user = UpdatableUserRepresentation{}
	user.ID = ptr("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	user.Username = ptr("username")
	user.Email = csjson.StringToOptional("username@company.com")
	user.Enabled = &boolTrue
	user.EmailVerified = &boolTrue
	user.PhoneNumber = csjson.StringToOptional("+415174234")
	user.PhoneNumberVerified = &boolTrue
	user.FirstName = ptr("Firstname")
	user.LastName = ptr("Lastname")
	user.Label = ptr("label")
	user.Gender = ptr("F")
	user.BirthDate = ptr("1990-12-28")
	user.Roles = &roles
	user.Locale = ptr("en")

	return user
}

func createValidRoleRepresentation() RoleRepresentation {
	boolTrue := true

	var role = RoleRepresentation{}
	role.ID = ptr("f467ed7c-0a1d-4eee-9bb8-669c6f89c0ee")
	role.Name = ptr("name")
	role.Description = ptr("description")
	role.ContainerID = ptr("12345678-abcd-beef-feed-123456781234")
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
		Operator:  ptr("operator"),
		DateTime:  nil,
		Status:    ptr("status"),
		Type:      ptr("type"),
		Nature:    ptr("nature"),
		ProofType: ptr("ZIP"),
		Comment:   ptr("comment"),
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
