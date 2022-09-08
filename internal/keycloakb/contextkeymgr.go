package keycloakb

type ContextKeyParameters struct {
	ID                    *string `mapstructure:"id"`
	Realm                 *string `mapstructure:"realm"`
	OnboardingRedirectURI *string `mapstructure:"onboardingRedirectURI,omitempty"`
	OnboardingClientID    *string `mapstructure:"onboardingClientID,omitempty"`
	RedirectMode          *bool   `mapstructure:"redirectMode,omitempty"`
}

type ContextKeyManager struct {
	contextKeys map[string]map[string]ContextKeyParameters
}

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

func (c *ContextKeyManager) GetOverride(realm string, contextKey string) (ContextKeyParameters, bool) {
	if contextKeyPerRealm, ok := c.contextKeys[realm]; ok {
		if res, ok := contextKeyPerRealm[contextKey]; ok {
			return res, true
		}
	}
	return ContextKeyParameters{}, false
}
