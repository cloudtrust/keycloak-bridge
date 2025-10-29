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

	idp := createTestApiIdp()
	idp.HrdSettings = &api.HrdSettingModel{
		IPRangesList: "192.168.0.1/24,127.0.0.1/8",
	}

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

	idp := createTestApiIdp()
	idp.HrdSettings = &api.HrdSettingModel{
		IPRangesList: "192.168.1.1/24",
	}

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

func TestGetIdentityProviderMappersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetIdentityProviderMappersEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mockIdpComponent.EXPECT().GetIdentityProviderMappers(ctx, realm, idpAlias).Return([]api.IdentityProviderMapperRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestCreateIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeCreateIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mapper := createTestApiIdpMapper()
	mapperJSON, _ := json.Marshal(mapper)
	req[reqBody] = string(mapperJSON)

	mockIdpComponent.EXPECT().CreateIdentityProviderMapper(ctx, realm, idpAlias, mapper).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestUpdateIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias
	req[prmMapper] = mapperID

	mapper := createTestApiIdpMapper()
	mapperJSON, _ := json.Marshal(mapper)
	req[reqBody] = string(mapperJSON)

	mockIdpComponent.EXPECT().UpdateIdentityProviderMapper(ctx, realm, idpAlias, mapperID, mapper).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestDeleteIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeDeleteIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias
	req[prmMapper] = mapperID

	mockIdpComponent.EXPECT().DeleteIdentityProviderMapper(ctx, realm, idpAlias, mapperID).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}
