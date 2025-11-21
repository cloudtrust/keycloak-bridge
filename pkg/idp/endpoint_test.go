package idp

import (
	"context"
	"encoding/json"
	"errors"
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

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
	}

	anyError := errors.New("any-error")

	t.Run("CreateIdentGetIdentityProviderMappersityProviderMapper - failure", func(t *testing.T) {
		mockIdpComponent.EXPECT().GetIdentityProviderMappers(ctx, realm, idpAlias).Return([]api.IdentityProviderMapperRepresentation{}, anyError)
		_, err := e(ctx, req)
		assert.Equal(t, anyError, err)
	})

	t.Run("CreateIdentGetIdentityProviderMappersityProviderMapper - failure", func(t *testing.T) {
		mockIdpComponent.EXPECT().GetIdentityProviderMappers(ctx, realm, idpAlias).Return([]api.IdentityProviderMapperRepresentation{}, nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestCreateIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeCreateIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
	}

	mapper := createTestApiIdpMapper()
	req[reqBody] = toJSON(mapper)

	anyError := errors.New("any-error")

	t.Run("Invalid JSON", func(t *testing.T) {
		req[reqBody] = "{-"
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Invalid mapper IDP alias", func(t *testing.T) {
		*mapper.IdentityProviderAlias = "not an alias"
		req[reqBody] = toJSON(mapper)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		*mapper.IdentityProviderAlias = idpAlias
	})

	t.Run("Invalid mapper name", func(t *testing.T) {
		*mapper.Name = "&$@"
		req[reqBody] = toJSON(mapper)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		*mapper.Name = "deviceId"
	})

	t.Run("CreateIdentityProviderMapper - failure", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mockIdpComponent.EXPECT().CreateIdentityProviderMapper(ctx, realm, idpAlias, mapper).Return(anyError)
		_, err := e(ctx, req)
		assert.Equal(t, anyError, err)
	})

	t.Run("CreateIdentityProviderMapper - success", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mockIdpComponent.EXPECT().CreateIdentityProviderMapper(ctx, realm, idpAlias, mapper).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestUpdateIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeUpdateIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
		prmMapper:   mapperID,
	}

	mapper := createTestApiIdpMapper()
	mapperJSON, _ := json.Marshal(mapper)
	req[reqBody] = string(mapperJSON)

	anyError := errors.New("any-error")

	t.Run("Invalid JSON", func(t *testing.T) {
		req[reqBody] = "{-"
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Invalid mapper IDP alias", func(t *testing.T) {
		*mapper.IdentityProviderAlias = "not an alias"
		req[reqBody] = toJSON(mapper)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		*mapper.IdentityProviderAlias = idpAlias
	})

	t.Run("invalid mapper name", func(t *testing.T) {
		*mapper.Name = "&$@"
		req[reqBody] = toJSON(mapper)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		*mapper.Name = "deviceId"
	})

	t.Run("invalid mapper ID", func(t *testing.T) {
		*mapper.ID = "not an ID"
		req[reqBody] = toJSON(mapper)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
		*mapper.ID = mapperID
	})

	t.Run("UpdateIdentityProviderMapper - failure", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mockIdpComponent.EXPECT().UpdateIdentityProviderMapper(ctx, realm, idpAlias, mapperID, mapper).Return(anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("UpdateIdentityProviderMapper - success", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mockIdpComponent.EXPECT().UpdateIdentityProviderMapper(ctx, realm, idpAlias, mapperID, mapper).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})
}

func TestDeleteIdentityProviderMapperEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockIdpComponent = mock.NewComponent(mockCtrl)

	var e = MakeDeleteIdentityProviderMapperEndpoint(mockIdpComponent)

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
		prmMapper:   mapperID,
	}

	anyError := errors.New("any-error")

	t.Run("DeleteIdentityProviderMapper - failure", func(t *testing.T) {
		mockIdpComponent.EXPECT().DeleteIdentityProviderMapper(ctx, realm, idpAlias, mapperID).Return(anyError)
		_, err := e(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("DeleteIdentityProviderMapper - success", func(t *testing.T) {
		mockIdpComponent.EXPECT().DeleteIdentityProviderMapper(ctx, realm, idpAlias, mapperID).Return(nil)
		_, err := e(ctx, req)
		assert.Nil(t, err)
	})

}
