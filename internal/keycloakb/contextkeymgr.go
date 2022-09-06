package keycloakb

import (
	"encoding/json"
)

type ContextKeyParameters struct {
	ID                    *string `json:"id"`
	Realm                 *string `json:"realm"`
	OnboardingRedirectURI *string `json:"onboardingRedirectURI,omitempty"`
	OnboardingClientID    *string `json:"onboardingClientID,omitempty"`
	RedirectMode          *bool   `json:"redirectMode,omitempty"`
}

type ContextKeyManager struct {
	contextKeys map[string]map[string]ContextKeyParameters
}

func MakeContextKeyManager(contextKeysConfig interface{}) (*ContextKeyManager, error) {
	var contextKeys []ContextKeyParameters
	mapContextKeys := map[string]map[string]ContextKeyParameters{}
	jsonConfig, err := json.Marshal(contextKeysConfig)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonConfig, &contextKeys)
	if err != nil {
		return nil, err
	}

	for _, contextKey := range contextKeys {
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
