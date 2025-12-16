package apiidp

import (
	"fmt"
	"strings"
	"testing"

	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
)

var (
	addReadTokenRoleOnCreate  = false
	alias                     = "trustid-idp"
	authenticateByDefault     = true
	displayName               = "MyTrustID"
	enabled                   = true
	firstBrokerLoginFlowAlias = "TID - first broker login"
	hideOnLogin               = true
	internalID                = "92546c68-c5df-439d-85f6-fe296165517b"
	linkOnly                  = false
	postBrokerLoginFlowAlias  = "TID - post login"
	providerID                = "oidc"
	storeToken                = false
	trustEmail                = false
)

func ptr(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}

func createTestIdpConfig() map[string]string {
	return map[string]string{
		"postBindingLogout":              "true",
		"postBindingResponse":            "true",
		"backchannelSupported":           "false",
		"caseSensitiveOriginalUsername":  "false",
		"idpEntityId":                    "value-tbd",
		"useMetadataDescriptorUrl":       "false",
		"loginHint":                      "false",
		"allowCreate":                    "true",
		"authnContextComparisonType":     "exact",
		"syncMode":                       "LEGACY",
		"singleSignOnServiceUrl":         "https://saml.sso.url/",
		"wantAuthnRequestsSigned":        "false",
		"allowedClockSkew":               "0",
		"artifactBindingResponse":        "false",
		"validateSignature":              "true",
		"signingCertificate":             "certificate",
		"nameIDPolicyFormat":             "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"entityId":                       "https://idp-staging.dev.trustid.ch/auth/realms/test",
		"signSpMetadata":                 "false",
		"wantAssertionsEncrypted":        "false",
		"sendClientIdOnLogout":           "false",
		"wantAssertionsSigned":           "true",
		"sendIdTokenOnLogout":            "true",
		"postBindingAuthnRequest":        "true",
		"forceAuthn":                     "false",
		"attributeConsumingServiceIndex": "0",
		"principalType":                  "SUBJECT",
	}
}

func createValideHrdSettings() HrdSettingModel {
	return HrdSettingModel{
		IPRangesList: "192.168.0.1/24,127.0.0.1/8",
	}
}

func createTestAPIIdp() IdentityProviderRepresentation {
	config := createTestIdpConfig()
	validHrdSetting := createValideHrdSettings()

	return IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  &addReadTokenRoleOnCreate,
		Alias:                     &alias,
		AuthenticateByDefault:     &authenticateByDefault,
		Config:                    config,
		DisplayName:               &displayName,
		Enabled:                   &enabled,
		FirstBrokerLoginFlowAlias: &firstBrokerLoginFlowAlias,
		HideOnLogin:               &hideOnLogin,
		InternalID:                &internalID,
		LinkOnly:                  &linkOnly,
		PostBrokerLoginFlowAlias:  &postBrokerLoginFlowAlias,
		ProviderID:                &providerID,
		StoreToken:                &storeToken,
		TrustEmail:                &trustEmail,
		HrdSettings:               &validHrdSetting,
	}
}

func createValidIdpMapper() IdentityProviderMapperRepresentation {
	return IdentityProviderMapperRepresentation{
		Config:                 map[string]string{"key1": "value1", "key2": "value2"},
		ID:                     ptr("88888888-4444-4444-4444-121212121212"),
		IdentityProviderAlias:  ptr("alias"),
		IdentityProviderMapper: ptr("mapper"),
		Name:                   ptr("name"),
	}
}

func createValidUserRepresentation() UserRepresentation {
	return UserRepresentation{
		ID:        ptr("user-id"),
		Username:  ptr("username"),
		FirstName: ptr("first name"),
		LastName:  ptr("last name"),
		Email:     ptr("em@il.ch"),
		Enabled:   ptrBool(true),
	}
}

func TestValidateConfig(t *testing.T) {
	t.Run("Nil config", func(t *testing.T) {
		assert.NoError(t, validateConfig(nil)())
	})
	t.Run("Empty config", func(t *testing.T) {
		assert.NoError(t, validateConfig(map[string]string{})())
	})
	t.Run("Valid config", func(t *testing.T) {
		assert.NoError(t, validateConfig(map[string]string{"key": "value"})())
	})
	t.Run("Invalid config", func(t *testing.T) {
		config := map[string]string{"singleSignOnServiceUrl": strings.Repeat("A", 1000000)}
		assert.Error(t, validateConfig(config)())
	})
}

func TestHRDSettingValidate(t *testing.T) {
	t.Run("Valid HRDSettingModel", func(t *testing.T) {
		settings := createValideHrdSettings()
		assert.NoError(t, settings.Validate())
	})

	var items []HrdSettingModel
	for range 4 {
		items = append(items, createValideHrdSettings())
	}
	items[0].IPRangesList = ""
	items[1].IPRangesList = "`!not a valid ipRangesList!`"
	items[2].Priority = -10571
	items[3].Priority = 27903

	for idx, item := range items {
		t.Run(fmt.Sprintf("HRDSettingModel case idx: %d", idx), func(t *testing.T) {
			assert.Error(t, item.Validate())
		})
	}
}

func TestIdentityProviderConversions(t *testing.T) {
	var apiIDP = createTestAPIIdp()
	var kcIDP = apiIDP.ConvertToKCIdentityProvider()
	var fullCycleConversionIDP = ConvertToAPIIdentityProvider(kcIDP)
	apiIDP.HrdSettings = nil // Not used in conversions
	assert.Equal(t, apiIDP, fullCycleConversionIDP)
}

func TestValidateIdentityProviderRepresentation(t *testing.T) {
	t.Run("Valid IDP provider", func(t *testing.T) {
		idp := createTestAPIIdp()
		err := idp.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid alias", func(t *testing.T) {
		idp := createTestAPIIdp()

		*idp.Alias = "0123456789abcdef0123456789abcdef"

		err := idp.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid alias", func(t *testing.T) {
		idp := createTestAPIIdp()

		*idp.Alias = "`!not a valid alias!`"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid providerId", func(t *testing.T) {
		idp := createTestAPIIdp()

		*idp.InternalID = "not an ID"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid config", func(t *testing.T) {
		idp := createTestAPIIdp()

		n := 1000000
		idp.Config = map[string]string{
			"singleSignOnServiceUrl": strings.Repeat("A", n),
		}

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid HRD IP ranges list", func(t *testing.T) {
		idp := createTestAPIIdp()

		idp.HrdSettings.IPRangesList = "not a list of IP ranges"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid HRD priority score", func(t *testing.T) {
		idp := createTestAPIIdp()

		idp.HrdSettings.Priority = -250

		err := idp.Validate()
		assert.Error(t, err)
	})
}

func TestIdentityProviderMappersConversions(t *testing.T) {
	t.Run("Single element conversion", func(t *testing.T) {
		apiIDPMapper := createValidIdpMapper()
		kcIDPMapper := apiIDPMapper.ConvertToKCIdentityProviderMapper()
		fullCycleConversionIDPMapper := convertToAPIIdentityProviderMapper(kcIDPMapper)
		assert.Equal(t, apiIDPMapper, fullCycleConversionIDPMapper)
	})
	t.Run("Nil slice conversion", func(t *testing.T) {
		assert.Len(t, ConvertToAPIIdentityProviderMappers(nil), 0)
	})
	t.Run("Empty slice conversion", func(t *testing.T) {
		assert.Len(t, ConvertToAPIIdentityProviderMappers([]kc.IdentityProviderMapperRepresentation{}), 0)
	})
	t.Run("Multiple elements conversion", func(t *testing.T) {
		kcIDPMapper := createValidIdpMapper().ConvertToKCIdentityProviderMapper()
		slice := []kc.IdentityProviderMapperRepresentation{kcIDPMapper, kcIDPMapper, kcIDPMapper}
		assert.Len(t, ConvertToAPIIdentityProviderMappers(slice), len(slice))
	})
}

func TestIdentityProviderMapperValidate(t *testing.T) {
	t.Run("Valid IDP mapper", func(t *testing.T) {
		idpMapper := createValidIdpMapper()
		assert.NoError(t, idpMapper.Validate())
	})

	var items []IdentityProviderMapperRepresentation
	for range 8 {
		items = append(items, createValidIdpMapper())
	}
	items[0].ID = ptr("")
	items[1].ID = ptr("idp-mapper")
	items[2].IdentityProviderAlias = nil
	items[3].IdentityProviderAlias = ptr("")
	items[4].IdentityProviderMapper = nil
	items[5].IdentityProviderMapper = ptr("")
	items[6].Name = nil
	items[7].Name = ptr("")

	for idx, item := range items {
		t.Run(fmt.Sprintf("IdentityProviderRepresentation case idx: %d", idx), func(t *testing.T) {
			assert.Error(t, item.Validate())
		})
	}
}

func TestUserRepresentationConversions(t *testing.T) {
	t.Run("Nil slice", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUserRepresentations(nil))
	})
	t.Run("Empty slice", func(t *testing.T) {
		assert.Nil(t, ConvertToAPIUserRepresentations([]kc.UserRepresentation{}))
	})
	t.Run("Multiple elements in slice", func(t *testing.T) {
		// We don't check
		user := createValidUserRepresentation().ConvertToKCUserRepresentation()
		kcSlice := []kc.UserRepresentation{user, user, user}
		assert.Len(t, ConvertToAPIUserRepresentations(kcSlice), len(kcSlice))
	})
	t.Run("Single element conversion", func(t *testing.T) {
		apiUser := createValidUserRepresentation()
		kcUser := apiUser.ConvertToKCUserRepresentation()
		assert.Equal(t, apiUser, ConvertToAPIUserRepresentation(kcUser))
	})
}
