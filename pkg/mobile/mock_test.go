package mobilepkg

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,AuthorizationManager=AuthorizationManager,IdentificationAuthorizationManager=IdentificationAuthorizationManager github.com/cloudtrust/keycloak-bridge/pkg/mobile KeycloakClient,AuthorizationManager,IdentificationAuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,TokenProvider=TokenProvider,AccountingClient=AccountingClient github.com/cloudtrust/keycloak-bridge/pkg/mobile Component,TokenProvider,AccountingClient
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditation.go -package=mock -mock_names=AccreditationsServiceClient=AccreditationsServiceClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient AccreditationsServiceClient
