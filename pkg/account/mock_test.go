package account

//go:generate mockgen -destination=./mock/account_keycloak_client.go -package=mock -mock_names=KeycloakAccountClient=KeycloakAccountClient github.com/cloudtrust/keycloak-bridge/pkg/account KeycloakAccountClient
//go:generate mockgen -destination=./mock/eventsdbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/database EventsDBModule
//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=AccountComponent=AccountComponent,Component=Component github.com/cloudtrust/keycloak-bridge/pkg/account AccountComponent,Component
//go:generate mockgen -destination=./mock/logger.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/keycloak-bridge/internal/keycloakb Logger
//go:generate mockgen -destination=./mock/internal.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
