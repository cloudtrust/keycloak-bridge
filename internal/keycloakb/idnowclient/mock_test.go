package idnowclient

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/client.go -package=mock -mock_names=HTTPClient=HTTPClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/idnowclient HTTPClient
