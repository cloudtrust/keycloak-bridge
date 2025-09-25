package keycloakb

import (
	"github.com/cloudtrust/common-service/v2/configuration"
)

// ContextKeyLoader interface
type ContextKeyLoader interface {
	GetContext(realm string, contextKey string) (configuration.RealmContextKey, bool)
	GetContextByCustomerRealm(customerRealm string) (configuration.RealmContextKey, bool)
}

// ContextKeyParameters struct
type ContextKeyParameters struct {
	ID                    *string
	IdentitiesRealm       *string
	CustomerRealm         *string
	IdentificationURI     *string
	OnboardingRedirectURI *string
	OnboardingClientID    *string
	IsRedirectMode        *bool
}

// ContextKeyManager struct
type ContextKeyManager struct {
	contextKeyLoader ContextKeyLoader
}

// MakeContextKeyManager creates a context key manager
func MakeContextKeyManager(contextKeyLoader ContextKeyLoader) *ContextKeyManager {
	return &ContextKeyManager{
		contextKeyLoader: contextKeyLoader,
	}
}

// GetOverride gets override values for the pair realm/context key
func (c *ContextKeyManager) GetOverride(realm string, contextKey string) (ContextKeyParameters, bool) {
	if res, ok := c.contextKeyLoader.GetContext(realm, contextKey); ok {
		return toContextKeyParameters(res), true
	}
	return ContextKeyParameters{}, false
}

// GetContextByCustomerRealm gets a context by its customer realm
func (c *ContextKeyManager) GetContextByCustomerRealm(realm string) (ContextKeyParameters, bool) {
	if res, ok := c.contextKeyLoader.GetContextByCustomerRealm(realm); ok && res.Config.Onboarding != nil {
		return toContextKeyParameters(res), true
	}
	return ContextKeyParameters{}, false
}

func toContextKeyParameters(ctxKey configuration.RealmContextKey) ContextKeyParameters {
	return ContextKeyParameters{
		ID:                    &ctxKey.ID,
		IdentitiesRealm:       &ctxKey.IdentitiesRealm,
		CustomerRealm:         &ctxKey.CustomerRealm,
		IdentificationURI:     ctxKey.Config.IdentificationURI,
		OnboardingRedirectURI: ctxKey.Config.Onboarding.RedirectURI,
		OnboardingClientID:    ctxKey.Config.Onboarding.ClientID,
		IsRedirectMode:        ctxKey.Config.Onboarding.IsRedirectMode,
	}
}
