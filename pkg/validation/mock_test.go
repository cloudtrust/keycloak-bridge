package validation

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,TokenProvider=TokenProvider,EventsDBModule=EventsDBModule,UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/validation Component,KeycloakClient,TokenProvider,EventsDBModule,UsersDetailsDBModule
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
//go:generate mockgen -destination=./mock/internal.go -package=mock -mock_names=AccreditationsModule=AccreditationsModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb AccreditationsModule
