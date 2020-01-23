package register

//go:generate mockgen -destination=./mock/register.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,ConfigurationDBModule=ConfigurationDBModule,UsersDBModule=UsersDBModule github.com/cloudtrust/keycloak-bridge/pkg/register Component,KeycloakClient,ConfigurationDBModule,UsersDBModule
//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client OidcTokenProvider
//go:generate mockgen -destination=./mock/database.go -package=mock -mock_names=EventsDBModule=EventsDBModule,Transaction=Transaction github.com/cloudtrust/common-service/database EventsDBModule,Transaction
//go:generate mockgen -destination=./mock/sqltypes.go -package=mock -mock_names=SQLRow=SQLRow github.com/cloudtrust/common-service/database/sqltypes SQLRow
//go:generate mockgen -destination=./mock/http.go -package=mock -mock_names=Handler=Handler,ResponseWriter=ResponseWriter net/http Handler,ResponseWriter
