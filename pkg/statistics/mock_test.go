package statistics

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc.go -package=mock -mock_names=KeycloakClient=KcClient github.com/cloudtrust/keycloak-bridge/pkg/statistics KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/statistics Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/common-service/security KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/security AuthorizationDBReader
