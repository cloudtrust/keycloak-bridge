package keycloakb

// ContextKeyParameters struct
type ContextKeyParameters struct {
	ID                    *string `mapstructure:"id"`
	Realm                 *string `mapstructure:"realm"`
	OnboardingRedirectURI *string `mapstructure:"onboardingRedirectURI,omitempty"`
	IdentificationURI     *string `mapstructure:"identificationURI,omitempty"`
	OnboardingClientID    *string `mapstructure:"onboardingClientID,omitempty"`
	RedirectMode          *bool   `mapstructure:"redirectMode,omitempty"`
}

// ContextKeyManager struct
type ContextKeyManager struct {
	contextKeys map[string]map[string]ContextKeyParameters
}

// MakeContextKeyManager creates a context key manager
func MakeContextKeyManager(confProvider func(interface{}) error) (*ContextKeyManager, error) {
	var ctxKeyConfig []ContextKeyParameters
	var err = confProvider(&ctxKeyConfig)
	if err != nil {
		return nil, err
	}
	var mapContextKeys = map[string]map[string]ContextKeyParameters{}
	for _, contextKey := range ctxKeyConfig {
		if _, ok := mapContextKeys[*contextKey.Realm]; !ok {
			mapContextKeys[*contextKey.Realm] = make(map[string]ContextKeyParameters)
		}
		mapContextKeys[*contextKey.Realm][*contextKey.ID] = contextKey
	}
	return &ContextKeyManager{
		contextKeys: mapContextKeys,
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
