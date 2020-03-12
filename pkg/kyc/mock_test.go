package kyc

//go:generate mockgen -destination=./mock/kyc.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,EventsDBModule=EventsDBModule,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/pkg/kyc Component,KeycloakClient,EventsDBModule,UsersDBModule
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow,Transaction=Transaction github.com/cloudtrust/common-service/database/sqltypes SQLRow,Transaction
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
//go:generate mockgen -destination=./mock/internal.go -package=mock -mock_names=AccreditationsModule=AccreditationsModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb AccreditationsModule
