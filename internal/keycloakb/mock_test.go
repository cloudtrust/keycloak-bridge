package keycloakb

import _ "github.com/golang/mock/mockgen/model"

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/cloudtrust/common-service/v2/metrics Histogram
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/configdbinstrumenting.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccredsKeycloakClient=AccredsKeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccredsKeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,KeycloakForTechnicalClient=KeycloakForTechnicalClient,Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient,KeycloakForTechnicalClient,Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=CloudtrustDB=CloudtrustDB,SQLRow=SQLRow,SQLRows=SQLRows github.com/cloudtrust/common-service/v2/database/sqltypes CloudtrustDB,SQLRow,SQLRows
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=EncrypterDecrypter=EncrypterDecrypter github.com/cloudtrust/common-service/v2/security EncrypterDecrypter
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/onboarding.go -package=mock -mock_names=OnboardingKeycloakClient=OnboardingKeycloakClient,KeycloakURIProvider=KeycloakURIProvider,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb OnboardingKeycloakClient,KeycloakURIProvider,UsersDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/toolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/httpclient.go -package=mock -mock_names=HttpClient=HttpClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb HttpClient

func ptr(value string) *string {
	return &value
}

func ptrInt(value int) *int {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}
