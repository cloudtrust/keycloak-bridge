package mobilepkg

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,UsersDetailsDBModule=UsersDetailsDBModule,AuthorizationManager=AuthorizationManager github.com/cloudtrust/keycloak-bridge/pkg/mobile KeycloakClient,UsersDetailsDBModule,AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,TokenProvider=TokenProvider github.com/cloudtrust/keycloak-bridge/pkg/mobile Component,TokenProvider
