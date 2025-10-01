package keycloakb

import (
	"context"
	"errors"

	"github.com/cloudtrust/common-service/v2/configuration"
)

var (
	errOnboardingNotConfigured = errors.New("context key onboarding misconfigured")
)

// ContextKeyLoader interface
type ContextKeyLoader interface {
	GetContextKey(ctx context.Context, ctxKeyID string, customerRealm string) (configuration.RealmContextKey, error)
	GetDefaultContextKeyForCustomerRealm(ctx context.Context, customerRealm string) (configuration.RealmContextKey, error)
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
func (c *ContextKeyManager) GetOverride(ctx context.Context, contextKey string, realm string) (ContextKeyParameters, error) {
	res, err := c.contextKeyLoader.GetContextKey(ctx, contextKey, realm)
	if err != nil {
		return ContextKeyParameters{}, err
	}
	return toContextKeyParameters(res), nil
}

// GetDefaultContextKeyByCustomerRealm gets the default context by its customer realm
func (c *ContextKeyManager) GetDefaultContextKeyByCustomerRealm(ctx context.Context, realm string) (ContextKeyParameters, error) {
	ctxKey, err := c.contextKeyLoader.GetDefaultContextKeyForCustomerRealm(ctx, realm)
	if err != nil {
		return ContextKeyParameters{}, err
	}
	if ctxKey.Config.Onboarding == nil {
		return ContextKeyParameters{}, errOnboardingNotConfigured
	}
	return toContextKeyParameters(ctxKey), nil
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
