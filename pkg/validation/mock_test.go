package validation

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,TokenProvider=TokenProvider,EventsDBModule=EventsDBModule,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/pkg/validation Component,KeycloakClient,TokenProvider,EventsDBModule,UsersDBModule
//go:generate mockgen -destination=./mock/database.go -package=mock -mock_names=Transaction=Transaction github.com/cloudtrust/common-service/database Transaction
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow github.com/cloudtrust/common-service/database/sqltypes SQLRow
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
