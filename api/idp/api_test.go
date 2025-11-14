package apiidp

import (
	"strings"
	"testing"

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

func createTestApiIdp() IdentityProviderRepresentation {
	config := createTestIdpConfig()
	ipRangesList := "192.168.0.1/24,127.0.0.1/8"
	priority := 0

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
		HrdSettings: &HrdSettingModel{
			IPRangesList: &ipRangesList,
			Priority:     &priority,
		},
	}
}

func TestValidateIdentityProviderRepresentation(t *testing.T) {

	t.Run("valid OIDC provider", func(t *testing.T) {
		idp := createTestApiIdp()

		err := idp.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid alias", func(t *testing.T) {
		idp := createTestApiIdp()

		*idp.Alias = "`!not a valid alias!`"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid providerId", func(t *testing.T) {
		idp := createTestApiIdp()

		*idp.InternalID = "not an ID"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid config", func(t *testing.T) {
		idp := createTestApiIdp()

		n := 1000000
		idp.Config = map[string]string{
			"singleSignOnServiceUrl": strings.Repeat("A", n),
		}

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid HRD IP ranges list", func(t *testing.T) {
		idp := createTestApiIdp()

		*idp.HrdSettings.IPRangesList = "not a list of IP ranges"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid HRD priority score", func(t *testing.T) {
		idp := createTestApiIdp()

		*idp.HrdSettings.Priority = -250

		err := idp.Validate()
		assert.Error(t, err)
	})

}
