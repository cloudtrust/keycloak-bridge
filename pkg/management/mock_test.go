package management

//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule
//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=ManagementComponent,KeycloakClient=KeycloakClient,EventsReader=EventsReader github.com/cloudtrust/keycloak-bridge/pkg/management Component,KeycloakClient,EventsReader
//go:generate mockgen -destination=./mock/eventdbmodule.go -package=mock -mock_names=EventsDBModule=EventDBModule github.com/cloudtrust/common-service/database EventsDBModule
//go:generate mockgen -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth,AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/security KeycloakClient,AuthorizationDBReader
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/log Logger
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=OpentracingClient=OpentracingClient,Finisher=Finisher github.com/cloudtrust/common-service/tracing OpentracingClient,Finisher
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/management KeycloakClient
//go:generate mockgen -destination=./mock/database.go -package=mock -mock_names=Transaction=Transaction github.com/cloudtrust/common-service/database/sqltypes Transaction
//go:generate mockgen -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/security AuthorizationDBReader
//go:generate mockgen -destination=./mock/usersdbmodule.go -package=mock -mock_names=UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/management UsersDetailsDBModule
