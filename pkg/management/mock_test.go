package management

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=ManagementComponent github.com/cloudtrust/keycloak-bridge/pkg/management Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventdbmodule.go -package=mock -mock_names=EventsDBModule=EventDBModule github.com/cloudtrust/common-service/v2/database EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/v2/security KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/tracing.go -package=mock -mock_names=OpentracingClient=OpentracingClient,Finisher=Finisher github.com/cloudtrust/common-service/v2/tracing OpentracingClient,Finisher
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/management KeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/database.go -package=mock -mock_names=Transaction=Transaction github.com/cloudtrust/common-service/v2/database/sqltypes Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/v2/security AuthorizationDBReader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/usersdbmodule.go -package=mock -mock_names=UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/management UsersDetailsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/onboardingmodule.go -package=mock -mock_names=OnboardingModule=OnboardingModule github.com/cloudtrust/keycloak-bridge/pkg/management OnboardingModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/glnverifier.go -package=mock -mock_names=GlnVerifier=GlnVerifier github.com/cloudtrust/keycloak-bridge/pkg/management GlnVerifier
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/authorizationmanager.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security AuthorizationManager

func ptr(value string) *string {
	return &value
}
