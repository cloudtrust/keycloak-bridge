package keycloakb

import (
	"context"
	"errors"
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
		ctx = context.TODO()
	)

	mockContextKeyLoader.EXPECT().GetContextKey(ctx, contextKeyConfig.ID, contextKeyConfig.CustomerRealm).Return(contextKeyConfig, nil).AnyTimes()
	mockContextKeyLoader.EXPECT().GetDefaultContextKeyForCustomerRealm(ctx, contextKeyConfig.CustomerRealm).Return(contextKeyConfig, nil).AnyTimes()

	t.Run("GetOverride", func(t *testing.T) {
		t.Run("Valid parameters", func(t *testing.T) {
			res, err := contextKeyManager.GetOverride(ctx, contextKeyConfig.ID, contextKeyConfig.CustomerRealm)
			assert.Nil(t, err)
			assert.NotNil(t, res.OnboardingRedirectURI)
		})

		t.Run("Unknown context key", func(t *testing.T) {
			mockContextKeyLoader.EXPECT().GetContextKey(ctx, "key1", "unknown-realm").Return(configuration.RealmContextKey{}, errors.New("any error"))
			_, err := contextKeyManager.GetOverride(ctx, "key1", "unknown-realm")
			assert.NotNil(t, err)
		})
	})

	t.Run("GetContextByCustomerRealm", func(t *testing.T) {
		t.Run("Valid parameters", func(t *testing.T) {
			res, err := contextKeyManager.GetDefaultContextKeyByCustomerRealm(ctx, contextKeyConfig.CustomerRealm)
			assert.Nil(t, err)
			assert.Equal(t, contextKeyConfig.ID, *res.ID)
		})

		t.Run("Unknown context key", func(t *testing.T) {
			errDummy := errors.New("dummy error")
			mockContextKeyLoader.EXPECT().GetDefaultContextKeyForCustomerRealm(ctx, "unknown-realm").Return(configuration.RealmContextKey{}, errDummy)
			_, err := contextKeyManager.GetDefaultContextKeyByCustomerRealm(ctx, "unknown-realm")
			assert.NotNil(t, err)
		})
	})
}
