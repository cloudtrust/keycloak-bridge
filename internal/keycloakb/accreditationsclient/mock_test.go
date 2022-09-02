package accreditationsclient

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/accreditationsclient.go -package=mock -mock_names=HTTPClient=HTTPClient github.com/cloudtrust/keycloak-bridge/internal/keycloakb/accreditationsclient HTTPClient
