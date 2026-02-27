package idp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestGetIdentityProviderEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var e = MakeGetIdentityProviderEndpoint(mocks.component)

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mocks.component.EXPECT().GetIdentityProvider(ctx, realm, idpAlias).Return(api.IdentityProviderRepresentation{}, nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestCreateIdentityProviderEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var e = mocks.newEndpoints().CreateIdentityProvider

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm

	idp := createTestAPIIdp()
	idp.HrdSettings = &api.HrdSettingModel{
		IPRangesList: ptr("192.168.0.1/24,127.0.0.1/8"),
		Priority:     0,
	}

	idpJSON, _ := json.Marshal(idp)
	req[reqBody] = string(idpJSON)

	mocks.component.EXPECT().CreateIdentityProvider(ctx, realm, idp).Return(nil)
	_, err := e(ctx, req)
	assert.Nil(t, err)
}

func TestUpdateIdentityProviderEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	idp := createTestAPIIdp()
	idp.HrdSettings = &api.HrdSettingModel{
		IPRangesList: ptr("192.168.1.1/24"),
		Priority:     0,
	}

	idpJSON, _ := json.Marshal(idp)
	req[reqBody] = string(idpJSON)

	mocks.component.EXPECT().UpdateIdentityProvider(ctx, realm, idpAlias, idp).Return(nil)
	_, err := mocks.newEndpoints().UpdateIdentityProvider(ctx, req)
	assert.Nil(t, err)
}

func TestDeleteIdentityProviderEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	var req = make(map[string]string)
	req[prmRealm] = realm
	req[prmProvider] = idpAlias

	mocks.component.EXPECT().DeleteIdentityProvider(ctx, realm, idpAlias).Return(nil)
	_, err := mocks.newEndpoints().DeleteIdentityProvider(ctx, req)
	assert.Nil(t, err)
}

func TestGetIdentityProviderMappersEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
	}

	anyError := errors.New("any-error")

	t.Run("CreateIdentGetIdentityProviderMappersityProviderMapper - failure", func(t *testing.T) {
		mocks.component.EXPECT().GetIdentityProviderMappers(ctx, realm, idpAlias).Return([]api.IdentityProviderMapperRepresentation{}, anyError)
		_, err := mocks.newEndpoints().GetIdentityProviderMappers(ctx, req)
		assert.Equal(t, anyError, err)
	})

	t.Run("CreateIdentGetIdentityProviderMappersityProviderMapper - failure", func(t *testing.T) {
		mocks.component.EXPECT().GetIdentityProviderMappers(ctx, realm, idpAlias).Return([]api.IdentityProviderMapperRepresentation{}, nil)
		_, err := mocks.newEndpoints().GetIdentityProviderMappers(ctx, req)
		assert.Nil(t, err)
	})
}

func TestCreateIdentityProviderMapperEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
	}

	mapper := createTestAPIIdpMapper()
	req[reqBody] = toJSON(mapper)

	anyError := errors.New("any-error")

	t.Run("Invalid JSON", func(t *testing.T) {
		req[reqBody] = "{-"
		_, err := mocks.newEndpoints().CreateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Invalid mapper IDP alias", func(t *testing.T) {
		*mapper.IdentityProviderAlias = "not an alias"
		req[reqBody] = toJSON(mapper)
		_, err := mocks.newEndpoints().CreateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
		*mapper.IdentityProviderAlias = idpAlias
	})

	t.Run("Invalid mapper name", func(t *testing.T) {
		*mapper.Name = "&$@"
		req[reqBody] = toJSON(mapper)
		_, err := mocks.newEndpoints().CreateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
		*mapper.Name = "deviceId"
	})

	t.Run("CreateIdentityProviderMapper - failure", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mocks.component.EXPECT().CreateIdentityProviderMapper(ctx, realm, idpAlias, mapper).Return(anyError)
		_, err := mocks.newEndpoints().CreateIdentityProviderMapper(ctx, req)
		assert.Equal(t, anyError, err)
	})

	t.Run("CreateIdentityProviderMapper - success", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mocks.component.EXPECT().CreateIdentityProviderMapper(ctx, realm, idpAlias, mapper).Return(nil)
		_, err := mocks.newEndpoints().CreateIdentityProviderMapper(ctx, req)
		assert.Nil(t, err)
	})
}

func TestUpdateIdentityProviderMapperEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
		prmMapper:   mapperID,
	}

	mapper := createTestAPIIdpMapper()
	mapperJSON, _ := json.Marshal(mapper)
	req[reqBody] = string(mapperJSON)

	anyError := errors.New("any-error")

	t.Run("Invalid JSON", func(t *testing.T) {
		req[reqBody] = "{-"
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("Invalid mapper IDP alias", func(t *testing.T) {
		*mapper.IdentityProviderAlias = "not an alias"
		req[reqBody] = toJSON(mapper)
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
		*mapper.IdentityProviderAlias = idpAlias
	})

	t.Run("invalid mapper name", func(t *testing.T) {
		*mapper.Name = "&$@"
		req[reqBody] = toJSON(mapper)
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
		*mapper.Name = "deviceId"
	})

	t.Run("invalid mapper ID", func(t *testing.T) {
		*mapper.ID = "not an ID"
		req[reqBody] = toJSON(mapper)
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
		*mapper.ID = mapperID
	})

	t.Run("UpdateIdentityProviderMapper - failure", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mocks.component.EXPECT().UpdateIdentityProviderMapper(ctx, realm, idpAlias, mapperID, mapper).Return(anyError)
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("UpdateIdentityProviderMapper - success", func(t *testing.T) {
		req[reqBody] = toJSON(mapper)
		mocks.component.EXPECT().UpdateIdentityProviderMapper(ctx, realm, idpAlias, mapperID, mapper).Return(nil)
		_, err := mocks.newEndpoints().UpdateIdentityProviderMapper(ctx, req)
		assert.Nil(t, err)
	})
}

func TestDeleteIdentityProviderMapperEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var realm = "test-community"
	var ctx = context.Background()

	req := map[string]string{
		prmRealm:    realm,
		prmProvider: idpAlias,
		prmMapper:   mapperID,
	}

	anyError := errors.New("any-error")

	t.Run("DeleteIdentityProviderMapper - failure", func(t *testing.T) {
		mocks.component.EXPECT().DeleteIdentityProviderMapper(ctx, realm, idpAlias, mapperID).Return(anyError)
		_, err := mocks.newEndpoints().DeleteIdentityProviderMapper(ctx, req)
		assert.NotNil(t, err)
	})

	t.Run("DeleteIdentityProviderMapper - success", func(t *testing.T) {
		mocks.component.EXPECT().DeleteIdentityProviderMapper(ctx, realm, idpAlias, mapperID).Return(nil)
		_, err := mocks.newEndpoints().DeleteIdentityProviderMapper(ctx, req)
		assert.Nil(t, err)
	})
}

func TestGetUsersWithAttributeEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		realm  = "test-community"
		ctx    = context.TODO()
		result = []api.UserRepresentation{{}, {}, {}, {}}
		req    = map[string]string{
			prmRealm:       realm,
			prmGroupName:   "group-name",
			prmAttribKey:   "key",
			prmAttribValue: "value",
		}
		anyError = errors.New("any-error")
	)

	t.Run("Missing both username and groups", func(t *testing.T) {
		_, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, map[string]string{})
		assert.Error(t, err)
	})
	t.Run("Attribute key provided when attribute value is missing", func(t *testing.T) {
		_, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, map[string]string{prmRealm: realm, prmUsername: "user", prmAttribKey: "a-key"})
		assert.Error(t, err)
	})
	t.Run("Attribute value provided when attribute key is missing", func(t *testing.T) {
		_, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, map[string]string{prmRealm: realm, prmUsername: "user", prmAttribValue: "a-value"})
		assert.Error(t, err)
	})
	t.Run("Error when requesting username without roles", func(t *testing.T) {
		mocks.component.EXPECT().GetUsersWithAttribute(ctx, realm, gomock.Any(), nil, gomock.Any(), ptrBool(false)).Return(nil, anyError)
		_, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, map[string]string{prmRealm: realm, prmUsername: "user", prmNeedRoles: "false"})
		assert.Error(t, err)
	})
	t.Run("Error when requesting username with roles", func(t *testing.T) {
		mocks.component.EXPECT().GetUsersWithAttribute(ctx, realm, gomock.Any(), nil, gomock.Any(), ptrBool(true)).Return(nil, anyError)
		_, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, map[string]string{prmRealm: realm, prmUsername: "user", prmNeedRoles: "true"})
		assert.Error(t, err)
	})
	t.Run("Success searching with attributes", func(t *testing.T) {
		mocks.component.EXPECT().GetUsersWithAttribute(ctx, realm, nil, ptr(req[prmGroupName]), map[string]string{req[prmAttribKey]: req[prmAttribValue]}, nil).Return(result, nil)
		res, err := mocks.newEndpoints().GetUsersWithAttribute(ctx, req)
		assert.NoError(t, err)
		assert.Len(t, res, len(result))
	})
}

func TestAddUserAttributesEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		realm  = "the-realm"
		userID = "the-user-id"
		ctx    = context.TODO()
	)

	t.Run("Missing body", func(t *testing.T) {
		_, err := mocks.newEndpoints().AddUserAttributes(ctx, map[string]string{})
		assert.Error(t, err)
	})
	t.Run("Body is not a JSON value for a string", func(t *testing.T) {
		_, err := mocks.newEndpoints().AddUserAttributes(ctx, map[string]string{prmRealm: realm, reqBody: `"string-instead-of-map"`})
		assert.Error(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.component.EXPECT().AddUserAttributes(ctx, realm, userID, map[string][]string{"key": {"attribute-value"}}).Return(nil)
		_, err := mocks.newEndpoints().AddUserAttributes(ctx, map[string]string{prmRealm: realm, prmUser: userID, reqBody: `{"key": ["attribute-value"]}`})
		assert.NoError(t, err)
	})
}

func TestDeleteUserAttributesEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		realm  = "the-realm"
		userID = "the-user-id"
		ctx    = context.TODO()
	)

	mocks.component.EXPECT().DeleteUserAttributes(ctx, realm, userID, []string{"key"}).Return(nil)
	_, err := mocks.newEndpoints().DeleteUserAttributes(ctx, map[string]string{prmRealm: realm, prmUser: userID, reqBody: `["key"]`})
	assert.NoError(t, err)
}

func TestGetUserEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		realm  = "test-community"
		ctx    = context.TODO()
		userID = "user-id"
	)

	t.Run("Missing mandatory parameter", func(t *testing.T) {
		_, err := mocks.newEndpoints().GetUser(ctx, map[string]string{
			prmRealm: realm,
			prmUser:  userID,
		})
		assert.Error(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.component.EXPECT().GetUser(ctx, realm, userID, gomock.Not(nil)).Return(api.UserRepresentation{}, nil)
		_, err := mocks.newEndpoints().GetUser(ctx, map[string]string{
			prmRealm:     realm,
			prmUser:      userID,
			prmGroupName: "group-name",
		})
		assert.NoError(t, err)
	})
}

func TestDeleteUserEndpoint(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		realm  = "test-community"
		ctx    = context.TODO()
		userID = "user-id"
		req    = map[string]string{
			prmRealm:     realm,
			prmUser:      userID,
			prmGroupName: "group-name",
		}
		errDummy = errors.New("dummy")
	)

	t.Run("Missing optional parameter", func(t *testing.T) {
		mocks.component.EXPECT().DeleteUser(ctx, realm, userID, nil).Return(errDummy)
		_, err := mocks.newEndpoints().DeleteUser(ctx, map[string]string{prmRealm: realm, prmUser: userID})
		assert.Error(t, err)
	})
	t.Run("Missing mandatory parameter", func(t *testing.T) {
		mocks.component.EXPECT().DeleteUser(ctx, realm, userID, gomock.Not(nil)).Return(nil)
		_, err := mocks.newEndpoints().DeleteUser(ctx, req)
		assert.NoError(t, err)
	})
}

func TestGetUserFederatedIdentitiesEndpoint(t *testing.T) {
	mocks := createMocks(t)
	defer mocks.finish()

	var (
		realm  = "test-community"
		ctx    = context.TODO()
		userID = "user-id-123"
		req    = map[string]string{
			prmRealm: realm,
			prmUser:  userID,
		}
		result   = createTestAPIFedIdentities()
		errDummy = errors.New("dummy")
	)

	t.Run("GetUserFederatedIdentities fails", func(t *testing.T) {
		mocks.component.EXPECT().GetUserFederatedIdentities(ctx, realm, userID).Return(nil, errDummy)
		_, err := mocks.newEndpoints().GetUserFederatedIdentities(ctx, req)
		assert.Equal(t, errDummy, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.component.EXPECT().GetUserFederatedIdentities(ctx, realm, userID).Return(result, nil)

		res, err := mocks.newEndpoints().GetUserFederatedIdentities(ctx, req)
		assert.NoError(t, err)

		resSlice, ok := res.([]api.FederatedIdentityRepresentation)
		assert.True(t, ok)
		assert.ElementsMatch(t, result, resSlice)
	})
}

func TestUnlinkShadowUserEndpoint(t *testing.T) {
	mocks := createMocks(t)
	defer mocks.finish()

	var (
		realm    = "test-community"
		ctx      = context.TODO()
		userID   = "user-id-123"
		provider = "test-provider"
		req      = map[string]string{
			prmRealm:    realm,
			prmUser:     userID,
			prmProvider: provider,
		}
		errDummy = errors.New("dummy")
	)

	t.Run("UnlinkShadowUser fails", func(t *testing.T) {
		mocks.component.EXPECT().UnlinkShadowUser(ctx, realm, userID, provider).Return(errDummy)
		_, err := mocks.newEndpoints().UnlinkShadowUser(ctx, req)
		assert.Error(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.component.EXPECT().UnlinkShadowUser(ctx, realm, userID, provider).Return(nil)

		_, err := mocks.newEndpoints().UnlinkShadowUser(ctx, req)
		assert.NoError(t, err)
	})
}
