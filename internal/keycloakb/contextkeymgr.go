package keycloakb

import (
	"fmt"
)

// ContextKeyParameters struct
type ContextKeyParameters struct {
	ID                    *string `mapstructure:"id"`
	Realm                 *string `mapstructure:"realm"`
	RegistrationRealm     *string `mapstructure:"registrationRealm,omitempty"`
	OnboardingRedirectURI *string `mapstructure:"onboardingRedirectURI,omitempty"`
	IdentificationURI     *string `mapstructure:"identificationURI,omitempty"`
	OnboardingClientID    *string `mapstructure:"onboardingClientID,omitempty"`
	RedirectMode          *bool   `mapstructure:"redirectMode,omitempty"`
}

// ContextKeyManager struct
type ContextKeyManager struct {
	contextKeys                map[string]map[string]ContextKeyParameters
	contextByRegistrationRealm map[string]ContextKeyParameters
}

// MakeContextKeyManager creates a context key manager
func MakeContextKeyManager(confProvider func(any) error) (*ContextKeyManager, error) {
	var ctxKeyConfig []ContextKeyParameters
	var err = confProvider(&ctxKeyConfig)
	if err != nil {
		return nil, err
	}
	var mapContextKeys = map[string]map[string]ContextKeyParameters{}
	var mapContextByRegistrationRealm = map[string]ContextKeyParameters{}
	for _, contextKey := range ctxKeyConfig {
		// Map by realm/contextKey
		if _, ok := mapContextKeys[*contextKey.Realm]; !ok {
			mapContextKeys[*contextKey.Realm] = make(map[string]ContextKeyParameters)
		}
		mapContextKeys[*contextKey.Realm][*contextKey.ID] = contextKey
		// Map by registration realm
		if contextKey.RegistrationRealm == nil {
			return nil, fmt.Errorf("Missing registration realm for context key %s", *contextKey.ID)
		}
		if _, ok := mapContextByRegistrationRealm[*contextKey.RegistrationRealm]; ok {
			return nil, fmt.Errorf("Registration realm %s is used more than once in configuration", *contextKey.RegistrationRealm)
		}
		mapContextByRegistrationRealm[*contextKey.RegistrationRealm] = contextKey
	}
	return &ContextKeyManager{
		contextKeys:                mapContextKeys,
		contextByRegistrationRealm: mapContextByRegistrationRealm,
	}, nil
}

// GetOverride gets override values for the pair realm/context key
func (c *ContextKeyManager) GetOverride(realm string, contextKey string) (ContextKeyParameters, bool) {
	if contextKeyPerRealm, ok := c.contextKeys[realm]; ok {
		if res, ok := contextKeyPerRealm[contextKey]; ok {
			return res, true
		}
	}
	return ContextKeyParameters{}, false
}

// GetContextByRegistrationRealm gets a context by its registration realm
func (c *ContextKeyManager) GetContextByRegistrationRealm(realm string) (ContextKeyParameters, bool) {
	if ctx, ok := c.contextByRegistrationRealm[realm]; ok {
		return ctx, true
	}
	return ContextKeyParameters{}, false
}
