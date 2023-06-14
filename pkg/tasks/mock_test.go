package tasks

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/tasks Component,KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/v2/security AuthorizationDBReader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/v2/security KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsreportermodule.go -package=mock -mock_names=AuditEventsReporterModule=AuditEventsReporterModule github.com/cloudtrust/common-service/v2/events AuditEventsReporterModule
