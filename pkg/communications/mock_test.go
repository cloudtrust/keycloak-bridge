package communications

//go:generate mockgen -destination=./mock/keycloak_communications_client.go -package=mock -mock_names=KeycloakCommunicationsClient=KeycloakCommunicationsClient github.com/cloudtrust/keycloak-bridge/pkg/communications KeycloakCommunicationsClient
//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/log Logger
