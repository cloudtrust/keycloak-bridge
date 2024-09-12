package statistics

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc.go -package=mock -mock_names=KeycloakClient=KcClient github.com/cloudtrust/keycloak-bridge/pkg/statistics KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/statistics Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/common-service/v2/security KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/v2/security AuthorizationDBReader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditationsclient.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/idnowclient.go -package=mock -mock_names=IdnowServiceClient=IdnowServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/idnowclient IdnowServiceClient

func ptr(value string) *string {
	return &value
}

func intPtr(value int) *int {
	return &value
}
