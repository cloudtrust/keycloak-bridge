package management

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/management.go -package=mock -mock_names=Component=ManagementComponent,KeycloakClient=KeycloakClient,OnboardingModule=OnboardingModule,GlnVerifier=GlnVerifier,UserProfileCache=UserProfileCache github.com/cloudtrust/keycloak-bridge/pkg/management Component,KeycloakClient,OnboardingModule,GlnVerifier,UserProfileCache
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsreportermodule.go -package=mock -mock_names=AuditEventsReporterModule=AuditEventsReporterModule github.com/cloudtrust/common-service/v2/events AuditEventsReporterModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/database.go -package=mock -mock_names=Transaction=Transaction github.com/cloudtrust/common-service/v2/database/sqltypes Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=KeycloakClient=KcClientAuth,AuthorizationDBReader=AuthorizationDBReader,AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security KeycloakClient,AuthorizationDBReader,AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/tracing.go -package=mock -mock_names=OpentracingClient=OpentracingClient,Finisher=Finisher github.com/cloudtrust/common-service/v2/tracing OpentracingClient,Finisher
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kctoolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditation.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient

func ptr(value string) *string {
	return &value
}
