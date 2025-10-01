package keycloakb

import (
	_ "github.com/golang/mock/mockgen/model"
)

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/cloudtrust/common-service/v2/metrics Histogram
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=CloudtrustDB=CloudtrustDB,SQLRow=SQLRow,SQLRows=SQLRows,Transaction=Transaction github.com/cloudtrust/common-service/v2/database/sqltypes CloudtrustDB,SQLRow,SQLRows,Transaction
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=EncrypterDecrypter=EncrypterDecrypter github.com/cloudtrust/common-service/v2/security EncrypterDecrypter
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloakb.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccredsKeycloakClient=AccredsKeycloakClient,KeycloakClient=KeycloakClient,KeycloakForTechnicalClient=KeycloakForTechnicalClient,Logger=Logger,HTTPClient=HTTPClient,OnboardingKeycloakClient=OnboardingKeycloakClient,KeycloakURIProvider=KeycloakURIProvider,ContextKeyLoader=ContextKeyLoader github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccredsKeycloakClient,KeycloakClient,KeycloakForTechnicalClient,Logger,HTTPClient,OnboardingKeycloakClient,KeycloakURIProvider,ContextKeyLoader
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/toolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditationsclient.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient

func ptr(value string) *string {
	return &value
}

func ptrInt(value int) *int {
	return &value
}

func ptrBool(value bool) *bool {
	return &value
}
