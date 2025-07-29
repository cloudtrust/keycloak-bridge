package idp

import (
	"context"
	"encoding/json"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetIdentityProviderEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetIdentityProviderEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mockIdpComponent.EXPECT().GetIdentityProvider(ctx, realm, idpAlias).Return(api.IdentityProviderRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestCreateIdentityProviderEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeCreateIdentityProviderEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm

	idp := testApiIdp()
	idpJSON, _ := json.Marshal(idp)
	req[reqBody] = string(idpJSON)

	mockIdpComponent.EXPECT().CreateIdentityProvider(ctx, realm, idp).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestUpdateIdentityProviderEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateIdentityProviderEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	idp := testApiIdp()
	idpJSON, _ := json.Marshal(idp)
	req[reqBody] = string(idpJSON)

	mockIdpComponent.EXPECT().UpdateIdentityProvider(ctx, realm, idpAlias, idp).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestDeleteIdentityProviderEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeDeleteIdentityProviderEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mockIdpComponent.EXPECT().DeleteIdentityProvider(ctx, realm, idpAlias).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}
