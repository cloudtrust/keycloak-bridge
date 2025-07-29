package apiidp

import (
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
	internalID                = "92546c68-c5df-439d-85f6-fe296165517b"
	linkOnly                  = false
	postBrokerLoginFlowAlias  = "TID - post login"
	providerID                = "oidc"
	storeToken                = false
	trustEmail                = false
)

func testIDP() IdentityProviderRepresentation {
	return IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate: &addReadTokenRoleOnCreate,
		Alias:                    &alias,
		AuthenticateByDefault:    &authenticateByDefault,
		Config: &map[string]interface{}{
			"acceptsPromptNoneForwardFromClient": "false",
			"authorizationUrl":                   "http://keycloak.local:8080/auth/realms/trustid/protocol/openid-connect/auth",
			"backchannelSupported":               "true",
			"clientAuthMethod":                   "client_secret_basic",
			"clientId":                           "test-community-sp",
			"clientSecret":                       "**********",
			"disableUserInfo":                    "false",
			"issuer":                             "http://keycloak.local:8080/auth/realms/trustid",
			"jwksUrl":                            "http://keycloak.local:8080/auth/realms/trustid/protocol/openid-connect/certs",
			"logoutUrl":                          "http://keycloak.local:8080/auth/realms/trustid/protocol/openid-connect/logout",
			"metadataDescriptorUrl":              "http://keycloak.local:8080/auth/realms/trustid/.well-known/openid-configuration",
			"pkceEnabled":                        "true",
			"pkceMethod":                         "S256",
			"syncMode":                           "FORCE",
			"tokenUrl":                           "http://keycloak.local:8080/auth/realms/trustid/protocol/openid-connect/token",
			"useJwksUrl":                         "true",
			"userInfoUrl":                        "http://keycloak.local:8080/auth/realms/trustid/protocol/openid-connect/userinfo",
			"validateSignature":                  "true",
		},
		DisplayName:               &displayName,
		Enabled:                   &enabled,
		FirstBrokerLoginFlowAlias: &firstBrokerLoginFlowAlias,
		InternalID:                &internalID,
		LinkOnly:                  &linkOnly,
		PostBrokerLoginFlowAlias:  &postBrokerLoginFlowAlias,
		ProviderID:                &providerID,
		StoreToken:                &storeToken,
		TrustEmail:                &trustEmail,
	}
}

func TestValidateIdentityProviderRepresentation(t *testing.T) {

	t.Run("valid OIDC provider", func(t *testing.T) {
		idp := testIDP()

		err := idp.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid alias", func(t *testing.T) {
		idp := testIDP()

		*idp.Alias = "`!not a valid alias!`"

		err := idp.Validate()
		assert.Error(t, err)
	})

	t.Run("invalid providerId", func(t *testing.T) {
		idp := testIDP()

		*idp.InternalID = "not an ID"

		err := idp.Validate()
		assert.Error(t, err)
	})

}
