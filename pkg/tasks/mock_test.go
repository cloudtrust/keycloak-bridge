package tasks

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,UsersDetailsDBModule=UsersDetailsDBModule github.com/cloudtrust/keycloak-bridge/pkg/tasks Component,KeycloakClient,UsersDetailsDBModule
//go:generate mockgen -destination=./mock/authentication_db_reader.go -package=mock -mock_names=AuthorizationDBReader=AuthorizationDBReader github.com/cloudtrust/common-service/security AuthorizationDBReader
//go:generate mockgen -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/security KeycloakClient
//go:generate mockgen -destination=./mock/dbase.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/common-service/database EventsDBModule
