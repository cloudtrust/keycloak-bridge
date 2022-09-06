package keycloakb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOverride(t *testing.T) {
	var key1 = "19251660-f869-11ec-b939-0242ac120002"
	var key2 = "19331779-1234-aabb-bcbc-0353ac230009"
	var realm1 = "my-first-realm"
	var realm2 = "my-second-realm"
	contextKeysConfig := []ContextKeyParameters{
		{ID: ptr(key1), Realm: ptr(realm1), OnboardingRedirectURI: ptr("http://localhost/")},
		{ID: ptr(key2), Realm: ptr(realm2), OnboardingClientID: ptr("theclient")},
	}
	contextKeyManager, _ := MakeContextKeyManager(contextKeysConfig)

	t.Run("Valid parameters", func(t *testing.T) {
		res, ok := contextKeyManager.GetOverride(realm1, key1)
		assert.True(t, ok)
		assert.NotNil(t, res.OnboardingRedirectURI)

		res, ok = contextKeyManager.GetOverride(realm2, key2)
		assert.True(t, ok)
		assert.NotNil(t, res.OnboardingClientID)
	})

	t.Run("Unknown context key", func(t *testing.T) {
		_, ok := contextKeyManager.GetOverride(realm1, key2)
		assert.False(t, ok)

		_, ok = contextKeyManager.GetOverride("unknown-realm", key1)
		assert.False(t, ok)
	})
}
