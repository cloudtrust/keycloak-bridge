package keycloakb

//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/cloudtrust/common-service/metrics Histogram
//go:generate mockgen -destination=./mock/configdbinstrumenting.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccredsKeycloakClient=AccredsKeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccredsKeycloakClient
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,KeycloakForTechnicalClient=KeycloakForTechnicalClient,Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient,KeycloakForTechnicalClient,Logger
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=CloudtrustDB=CloudtrustDB,SQLRow=SQLRow,SQLRows=SQLRows github.com/cloudtrust/common-service/database/sqltypes CloudtrustDB,SQLRow,SQLRows
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=EncrypterDecrypter=EncrypterDecrypter github.com/cloudtrust/common-service/security EncrypterDecrypter
//go:generate mockgen -destination=./mock/onboarding.go -package=mock -mock_names=OnboardingKeycloakClient=OnboardingKeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb OnboardingKeycloakClient
//go:generate mockgen -destination=./mock/toolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/toolbox OidcTokenProvider
