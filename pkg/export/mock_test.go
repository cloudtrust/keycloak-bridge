package export

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/export.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,RealmExporter=RealmExporter,Storage=Storage github.com/cloudtrust/keycloak-bridge/pkg/export Component,KeycloakClient,RealmExporter,Storage
