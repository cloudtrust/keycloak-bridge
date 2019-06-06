package events

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=Component=Component github.com/cloudtrust/keycloak-bridge/pkg/events Component
//go:generate mockgen -destination=./mock/dbmodule.go -package=mock -mock_names=EventsDBModule=EventsDBModule github.com/cloudtrust/keycloak-bridge/internal/keycloakb EventsDBModule
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/common-service/security KeycloakClient
//go:generate mockgen -destination=./mock/dbevents.go -package=mock -mock_names=CloudtrustDB=DBEvents github.com/cloudtrust/common-service/database CloudtrustDB
//go:generate mockgen -destination=./mock/writedb.go -package=mock -mock_names=EventsDBModule=WriteDBModule  github.com/cloudtrust/common-service/database EventsDBModule
