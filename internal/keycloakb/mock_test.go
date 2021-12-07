package keycloakb

import _ "github.com/golang/mock/mockgen/model"

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/cloudtrust/common-service/v2/metrics Histogram
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/configdbinstrumenting.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccredsKeycloakClient=AccredsKeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccredsKeycloakClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,KeycloakForTechnicalClient=KeycloakForTechnicalClient,Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient,KeycloakForTechnicalClient,Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/sqltypes.go -package=mock -mock_names=CloudtrustDB=CloudtrustDB,SQLRow=SQLRow,SQLRows=SQLRows github.com/cloudtrust/common-service/v2/database/sqltypes CloudtrustDB,SQLRow,SQLRows
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/security.go -package=mock -mock_names=EncrypterDecrypter=EncrypterDecrypter github.com/cloudtrust/common-service/v2/security EncrypterDecrypter
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/onboarding.go -package=mock -mock_names=OnboardingKeycloakClient=OnboardingKeycloakClient,KeycloakURIProvider=KeycloakURIProvider github.com/cloudtrust/keycloak-bridge/internal/keycloakb OnboardingKeycloakClient,KeycloakURIProvider
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/toolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
