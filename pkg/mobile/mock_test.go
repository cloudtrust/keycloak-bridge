package mobilepkg

//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakAccountClient=KeycloakAccountClient,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/pkg/mobile KeycloakAccountClient,UsersDBModule
//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/mobile Component
