package mobilepkg

//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/pkg/mobile KeycloakClient,UsersDBModule
//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component,TokenProvider=TokenProvider github.com/cloudtrust/keycloak-bridge/pkg/mobile Component,TokenProvider
