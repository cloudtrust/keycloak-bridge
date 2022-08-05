package account

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccreditationsServiceClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakAccountClient=KeycloakAccountClient,KeycloakTechnicalClient=KeycloakTechnicalClient,UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/account KeycloakAccountClient,KeycloakTechnicalClient,UsersDetailsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/v2/database EventsDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,GlnVerifier=GlnVerifier github.com/cloudtrust/keycloak-bridge/pkg/account Component,GlnVerifier
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logger.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb Logger
