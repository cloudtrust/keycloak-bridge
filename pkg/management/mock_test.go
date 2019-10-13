package management

//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=ManagementComponent=ManagementComponent github.com/cloudtrust/keycloak-bridge/pkg/management ManagementComponent
//go:generate mockgen -destination=./mock/eventdbmodule.go -package=mock -mock_names=EventsDBModule=EventDBModule github.com/cloudtrust/common-service/database EventsDBModule
//go:generate mockgen -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/security KeycloakClient
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/log Logger
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=OpentracingClient=OpentracingClient,Finisher=Finisher github.com/cloudtrust/common-service/tracing OpentracingClient,Finisher
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/management KeycloakClient
