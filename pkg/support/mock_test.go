package support

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/support Component,KeycloakClient
