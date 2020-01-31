package kyc

//go:generate mockgen -destination=./mock/register.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,ConfigurationDBModule=ConfigurationDBModule github.com/cloudtrust/keycloak-bridge/pkg/kyc Component,KeycloakClient,ConfigurationDBModule
//go:generate mockgen -destination=./mock/bridge.go -package=mock -mock_names=UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb UsersDBModule
//go:generate mockgen -destination=./mock/database.go -package=mock -mock_names=EventsDBModule=EventsDBModule,Transaction=Transaction github.com/cloudtrust/common-service/database EventsDBModule,Transaction
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow github.com/cloudtrust/common-service/database/sqltypes SQLRow
//go:generate mockgen -destination=./mock/security.go -package=mock -mock_names=AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/security AuthorizationManager
