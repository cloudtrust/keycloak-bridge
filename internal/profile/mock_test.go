package profile

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/gln.go -package=mock -mock_names=GlnVerifier=GlnVerifier github.com/cloudtrust/keycloak-bridge/internal/business GlnVerifier
