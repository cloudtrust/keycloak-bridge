package validation

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,TokenProvider=TokenProvider,ArchiveDBModule=ArchiveDBModule,ConfigurationDBModule=ConfigurationDBModule,UserProfileCache=UserProfileCache github.com/cloudtrust/keycloak-bridge/pkg/validation Component,KeycloakClient,TokenProvider,ArchiveDBModule,ConfigurationDBModule,UserProfileCache
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditationsclient.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsreportermodule.go -package=mock -mock_names=AuditEventsReporterModule=AuditEventsReporterModule github.com/cloudtrust/common-service/v2/events AuditEventsReporterModule

func ptr(value string) *string {
	return &value
}
