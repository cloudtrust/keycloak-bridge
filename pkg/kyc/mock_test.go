package kyc

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kyc.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,ArchiveDBModule=ArchiveDBModule,ConfigDBModule=ConfigDBModule,UserProfileCache=UserProfileCache github.com/cloudtrust/keycloak-bridge/pkg/kyc Component,KeycloakClient,ArchiveDBModule,ConfigDBModule,UserProfileCache
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow,Transaction=Transaction github.com/cloudtrust/common-service/v2/database/sqltypes SQLRow,Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/middleware.go -package=mock -mock_names=EndpointAvailabilityChecker=EndpointAvailabilityChecker github.com/cloudtrust/common-service/v2/middleware EndpointAvailabilityChecker
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditationsclient.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsreportermodule.go -package=mock -mock_names=AuditEventsReporterModule=AuditEventsReporterModule github.com/cloudtrust/common-service/v2/events AuditEventsReporterModule
