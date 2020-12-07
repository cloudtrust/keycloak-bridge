package communications

//go:generate mockgen -destination=./mock/keycloak_communications_client.go -package=mock -mock_names=KeycloakCommunicationsClient=KeycloakCommunicationsClient github.com/cloudtrust/keycloak-bridge/pkg/communications KeycloakCommunicationsClient
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/log Logger

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/communications Component

//go:generate mockgen -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/security KeycloakClient
//go:generate mockgen -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/security AuthorizationDBReader
