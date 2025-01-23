package configuration

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/configuration/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMakeGetIdentificationURIEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	realm := "realm"
	contextKey := "context-key"

	mockConfigurationComponent := mock.NewComponent(mockCtrl)
	mockConfigurationComponent.EXPECT().GetIdentificationURI(context.Background(), realm, contextKey)

	m := map[string]string{}
	m[prmRealmName] = realm
	m[prmContextKey] = contextKey

	_, err := MakeGetIdentificationURIEndpoint(mockConfigurationComponent)(context.Background(), m)
	assert.Nil(t, err)
}
