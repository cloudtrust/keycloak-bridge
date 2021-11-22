package register

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/register.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,ConfigurationDBModule=ConfigurationDBModule,GlnVerifier=GlnVerifier github.com/cloudtrust/keycloak-bridge/pkg/register Component,KeycloakClient,ConfigurationDBModule,GlnVerifier
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/bridge.go -package=mock -mock_names=UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb UsersDetailsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/database.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/database EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow,Transaction=Transaction github.com/cloudtrust/common-service/database/sqltypes SQLRow,Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/http.go -package=mock -mock_names=Handler=Handler,ResponseWriter=ResponseWriter net/http Handler,ResponseWriter
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/onboardingmodule.go -package=mock -mock_names=OnboardingModule=OnboardingModule github.com/cloudtrust/keycloak-bridge/pkg/register OnboardingModule
