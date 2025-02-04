package configuration

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/configuration.go -package=mock -mock_names=Component=Component,ContextKeyManager=ContextKeyManager github.com/cloudtrust/keycloak-bridge/pkg/configuration Component,ContextKeyManager

func ptr(value string) *string {
	return &value
}
