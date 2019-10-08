package keycloakb

//go:generate mockgen -destination=./mock/configdbmodule.go -package=mock -mock_names=DBConfiguration=DBConfiguration github.com/cloudtrust/keycloak-bridge/internal/keycloakb DBConfiguration
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient
