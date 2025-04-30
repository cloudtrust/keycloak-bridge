package keycloakb

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeContextKeyManager(t *testing.T) {
	var key1 = "19251660-f869-11ec-b939-0242ac120002"
	var key2 = "19331779-1234-aabb-bcbc-0353ac230009"
	var realm1 = "my-first-realm"
	var realm2 = "my-second-realm"

	t.Run("Configuration provider fails", func(t *testing.T) {
		_, err := MakeContextKeyManager(func(rawVal any) error {
			return errors.New("any error")
		})
		assert.NotNil(t, err)
	})
	t.Run("Configuration is missing RegistrationRealm", func(t *testing.T) {
		contextKeysConfig := []ContextKeyParameters{
			{ID: ptr(key1), Realm: ptr(realm1), OnboardingRedirectURI: ptr("http://localhost/")},
			{ID: ptr(key2), Realm: ptr(realm2), OnboardingClientID: ptr("theclient"), RegistrationRealm: ptr("dummy2")},
		}
		_, err := MakeContextKeyManager(func(rawVal any) error {
			*(rawVal.(*[]ContextKeyParameters)) = contextKeysConfig
			return nil
		})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), key1)
	})
	t.Run("Configuration is using same RegistrationRealm twice", func(t *testing.T) {
		var dummyRealm = "dummy"
		contextKeysConfig := []ContextKeyParameters{
			{ID: ptr(key1), Realm: ptr(realm1), OnboardingRedirectURI: ptr("http://localhost/"), RegistrationRealm: ptr(dummyRealm)},
			{ID: ptr(key2), Realm: ptr(realm2), OnboardingClientID: ptr("theclient"), RegistrationRealm: ptr(dummyRealm)},
		}
		_, err := MakeContextKeyManager(func(rawVal any) error {
			*(rawVal.(*[]ContextKeyParameters)) = contextKeysConfig
			return nil
		})
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), dummyRealm)
	})
}

func TestGetOverride(t *testing.T) {
	var key1 = "19251660-f869-11ec-b939-0242ac120002"
	var key2 = "19331779-1234-aabb-bcbc-0353ac230009"
	var realm1 = "my-first-realm"
	var realm2 = "my-second-realm"
	contextKeysConfig := []ContextKeyParameters{
		{ID: ptr(key1), Realm: ptr(realm1), OnboardingRedirectURI: ptr("http://localhost/"), RegistrationRealm: ptr("dummy1")},
		{ID: ptr(key2), Realm: ptr(realm2), OnboardingClientID: ptr("theclient"), RegistrationRealm: ptr("dummy2")},
	}
	contextKeyManager, err := MakeContextKeyManager(func(rawVal any) error {
		*(rawVal.(*[]ContextKeyParameters)) = contextKeysConfig
		return nil
	})
	assert.Nil(t, err)

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

func TestGetContextByRegistrationRealm(t *testing.T) {
	var key1 = "19251660-f869-11ec-b939-0242ac120002"
	var key2 = "19331779-1234-aabb-bcbc-0353ac230009"
	var realm1 = "my-first-realm"
	var realm2 = "my-second-realm"

	contextKeysConfig := []ContextKeyParameters{
		{ID: ptr(key1), Realm: ptr("dummyRealm1"), RegistrationRealm: ptr(realm1), OnboardingRedirectURI: ptr("http://localhost/")},
		{ID: ptr(key2), Realm: ptr("dummyRealm2"), RegistrationRealm: ptr(realm2), OnboardingClientID: ptr("theclient")},
	}

	// Fix configuration
	contextKeysConfig[1].RegistrationRealm = ptr(realm2)
	contextKeyManager, err := MakeContextKeyManager(func(rawVal any) error {
		*(rawVal.(*[]ContextKeyParameters)) = contextKeysConfig
		return nil
	})
	assert.Nil(t, err)

	t.Run("Valid parameters", func(t *testing.T) {
		res, ok := contextKeyManager.GetContextByRegistrationRealm(realm1)
		assert.True(t, ok)
		assert.Equal(t, key1, *res.ID)

		res, ok = contextKeyManager.GetContextByRegistrationRealm(realm2)
		assert.True(t, ok)
		assert.Equal(t, key2, *res.ID)
	})

	t.Run("Unknown context key", func(t *testing.T) {
		_, ok := contextKeyManager.GetContextByRegistrationRealm("unknown-realm")
		assert.False(t, ok)
	})
}
