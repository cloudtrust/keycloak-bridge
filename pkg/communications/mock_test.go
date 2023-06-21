package communications

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_communications_client.go -package=mock -mock_names=KeycloakCommunicationsClient=KeycloakCommunicationsClient,Component=Component github.com/cloudtrust/keycloak-bridge/pkg/communications KeycloakCommunicationsClient,Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth,AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/v2/security KeycloakClient,AuthorizationDBReader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-oidc.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
