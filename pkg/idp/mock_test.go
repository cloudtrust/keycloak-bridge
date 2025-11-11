package idp

import "encoding/json"

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_idp_client.go -package=mock -mock_names=KeycloakIdpClient=KeycloakIdpClient,Component=Component github.com/cloudtrust/keycloak-bridge/pkg/idp KeycloakIdpClient,Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth,AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/v2/security KeycloakClient,AuthorizationDBReader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-oidc.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider,ComponentTool=ComponentTool github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider,ComponentTool

func ptr(value string) *string {
	return &value
}

func toJSON(data any) string {
	bytes, _ := json.Marshal(data)
	return string(bytes)
}
