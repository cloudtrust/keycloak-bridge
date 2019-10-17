package keycloakb

//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/cloudtrust/common-service/metrics Histogram
//go:generate mockgen -destination=./mock/configdbinstrumenting.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen -destination=./mock/configdbmodule.go -package=mock -mock_names=DBConfiguration=DBConfiguration github.com/cloudtrust/keycloak-bridge/internal/keycloakb DBConfiguration
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb KeycloakClient
