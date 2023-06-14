package account

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakAccountClient=KeycloakAccountClient,KeycloakTechnicalClient=KeycloakTechnicalClient github.com/cloudtrust/keycloak-bridge/pkg/account KeycloakAccountClient,KeycloakTechnicalClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,GlnVerifier=GlnVerifier,UserProfileCache=UserProfileCache github.com/cloudtrust/keycloak-bridge/pkg/account Component,GlnVerifier,UserProfileCache
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsreportermodule.go -package=mock -mock_names=AuditEventsReporterModule=AuditEventsReporterModule github.com/cloudtrust/common-service/v2/events AuditEventsReporterModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logger.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditation.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient
