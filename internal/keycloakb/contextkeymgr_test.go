package keycloakb

import (
	"testing"

	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestContextKeyManager(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	var (
		mockContextKeyLoader = mock.NewContextKeyLoader(mockCtrl)
		contextKeyManager    = MakeContextKeyManager(mockContextKeyLoader)

		contextKeyConfig = configuration.RealmContextKey{
			ID:              "key1",
			IdentitiesRealm: "the-first",
			CustomerRealm:   "first-customer-realm", Config: configuration.ContextKeyConfiguration{
				Onboarding: &configuration.ContextKeyConfOnboarding{
					RedirectURI:    ptr("http://localhost/"),
					ClientID:       ptr("the-client-1"),
					IsRedirectMode: ptrBool(true),
				},
			},
		}
	)

	mockContextKeyLoader.EXPECT().GetContext(contextKeyConfig.CustomerRealm, contextKeyConfig.ID).Return(contextKeyConfig, true).AnyTimes()
	mockContextKeyLoader.EXPECT().GetContextByCustomerRealm(contextKeyConfig.CustomerRealm).Return(contextKeyConfig, true).AnyTimes()

	t.Run("GetOverride", func(t *testing.T) {
		t.Run("Valid parameters", func(t *testing.T) {
			res, ok := contextKeyManager.GetOverride(contextKeyConfig.CustomerRealm, contextKeyConfig.ID)
			assert.True(t, ok)
			assert.NotNil(t, res.OnboardingRedirectURI)
		})

		t.Run("Unknown context key", func(t *testing.T) {
			mockContextKeyLoader.EXPECT().GetContext("unknown-realm", "key1").Return(configuration.RealmContextKey{}, false)
			_, ok := contextKeyManager.GetOverride("unknown-realm", "key1")
			assert.False(t, ok)
		})
	})

	t.Run("GetContextByCustomerRealm", func(t *testing.T) {
		t.Run("Valid parameters", func(t *testing.T) {
			res, ok := contextKeyManager.GetContextByCustomerRealm(contextKeyConfig.CustomerRealm)
			assert.True(t, ok)
			assert.Equal(t, contextKeyConfig.ID, *res.ID)
		})

		t.Run("Unknown context key", func(t *testing.T) {
			mockContextKeyLoader.EXPECT().GetContextByCustomerRealm("unknown-realm").Return(configuration.RealmContextKey{}, false)
			_, ok := contextKeyManager.GetContextByCustomerRealm("unknown-realm")
			assert.False(t, ok)
		})
	})
}
