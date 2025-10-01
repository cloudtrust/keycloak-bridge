package configuration

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
	"github.com/cloudtrust/keycloak-bridge/pkg/register/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	contextKeyMgr *mock.ContextKeyManager
}

func createMocks(mockCtrl *gomock.Controller) *componentMocks {
	return &componentMocks{
		contextKeyMgr: mock.NewContextKeyManager(mockCtrl),
	}
}

func (mocks *componentMocks) createComponent() *component {
	return NewComponent(mocks.contextKeyMgr, log.NewNopLogger()).(*component)
}

func TestGetIdentificationURI(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mocks := createMocks(mockCtrl)
	component := mocks.createComponent()

	realm := "realm"
	contextKey := "context-key"
	identificationURI := "identification-uri"
	ctx := context.TODO()

	t.Run("Invalid context key", func(t *testing.T) {
		mocks.contextKeyMgr.EXPECT().GetOverride(ctx, realm, contextKey).Return(keycloakb.ContextKeyParameters{}, errors.New("dummy"))

		_, err := component.GetIdentificationURI(ctx, realm, contextKey)
		assert.NotNil(t, err)
	})

	t.Run("No identification URI", func(t *testing.T) {
		mocks.contextKeyMgr.EXPECT().GetOverride(ctx, realm, contextKey).Return(keycloakb.ContextKeyParameters{
			ID:                ptr(contextKey),
			IdentitiesRealm:   &realm,
			IdentificationURI: nil,
		}, nil)

		_, err := component.GetIdentificationURI(ctx, realm, contextKey)
		assert.NotNil(t, err)
	})

	t.Run("Empty identification URI", func(t *testing.T) {
		mocks.contextKeyMgr.EXPECT().GetOverride(ctx, realm, contextKey).Return(keycloakb.ContextKeyParameters{
			ID:                ptr(contextKey),
			IdentitiesRealm:   &realm,
			IdentificationURI: ptr(""),
		}, nil)

		_, err := component.GetIdentificationURI(ctx, realm, contextKey)
		assert.NotNil(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.contextKeyMgr.EXPECT().GetOverride(ctx, realm, contextKey).Return(keycloakb.ContextKeyParameters{
			ID:                ptr(contextKey),
			IdentitiesRealm:   &realm,
			IdentificationURI: ptr(identificationURI),
		}, nil)

		uri, err := component.GetIdentificationURI(ctx, realm, contextKey)
		assert.Nil(t, err)
		assert.Equal(t, identificationURI, uri)
	})
}
