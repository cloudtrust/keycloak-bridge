package register

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/register.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,ConfigurationDBModule=ConfigurationDBModule,GlnVerifier=GlnVerifier,ContextKeyManager=ContextKeyManager github.com/cloudtrust/keycloak-bridge/pkg/register Component,KeycloakClient,ConfigurationDBModule,GlnVerifier,ContextKeyManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/database.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/v2/database EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow,Transaction=Transaction github.com/cloudtrust/common-service/v2/database/sqltypes SQLRow,Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/http.go -package=mock -mock_names=Handler=Handler,ResponseWriter=ResponseWriter net/http Handler,ResponseWriter
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/onboardingmodule.go -package=mock -mock_names=OnboardingModule=OnboardingModule github.com/cloudtrust/keycloak-bridge/pkg/register OnboardingModule

func ptr(value string) *string {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}
