package idp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	errorhandler "github.com/cloudtrust/common-service/v2/errors"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const (
	realmName = "test"

	idpAlias = "0123456789abcdef0123456789abcdef"
	mapperID = "5b3f0a5d-a59d-4aff-8932-aa70f2806f01"

	compID           = "5b3f0a5d-a59d-4aff-8932-aa70f2806f04"
	compProviderType = "org.keycloak.services.ui.extend.UiTabProvider"
	compProviderID   = "Home-realm discovery settings"
	compConfigName   = "hrdSettings"

	accessToken  = "TOKEN=="
	fedUserID1   = "fed-user-1"
	fedUserID2   = "fed-user-2"
	fedUsername1 = "federated-user-1"
	fedUsername2 = "federated-user-2"
	fedProvider1 = "provider-1"
	fedProvider2 = "provider-2"
)

func ptrBool(value bool) *bool {
	return &value
}

func createTestKcIdp() kc.IdentityProviderRepresentation {
	return kc.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  ptrBool(false),
		Alias:                     ptr(idpAlias),
		AuthenticateByDefault:     ptrBool(false),
		DisplayName:               ptr("TEST"),
		Enabled:                   ptrBool(false),
		FirstBrokerLoginFlowAlias: ptr("first broker login"),
		HideOnLogin:               ptrBool(true),
		InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  ptrBool(false),
		PostBrokerLoginFlowAlias:  ptr("post broker login"),
		ProviderID:                ptr("oidc"),
		StoreToken:                ptrBool(false),
		TrustEmail:                ptrBool(false),
	}
}

func createTestAPIIdp() api.IdentityProviderRepresentation {
	return api.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  ptrBool(false),
		Alias:                     ptr(idpAlias),
		AuthenticateByDefault:     ptrBool(false),
		DisplayName:               ptr("TEST"),
		Enabled:                   ptrBool(false),
		FirstBrokerLoginFlowAlias: ptr("first broker login"),
		HideOnLogin:               ptrBool(true),
		InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  ptrBool(false),
		PostBrokerLoginFlowAlias:  ptr("post broker login"),
		ProviderID:                ptr("oidc"),
		StoreToken:                ptrBool(false),
		TrustEmail:                ptrBool(false),
	}
}

func createTestKcIdpMapper() kc.IdentityProviderMapperRepresentation {
	return kc.IdentityProviderMapperRepresentation{
		ID:                     ptr(mapperID),
		Name:                   ptr("deviceId"),
		IdentityProviderAlias:  ptr(idpAlias),
		IdentityProviderMapper: ptr("ct-saml-in-memory-attribute-idp-mapper"),
		Config: map[string]string{
			"syncMode":       "FORCE",
			"auth.note.name": "deviceId",
			"type":           "STRING",
			"attribute.name": "deviceId",
		},
	}
}

func createTestAPIIdpMapper() api.IdentityProviderMapperRepresentation {
	return api.IdentityProviderMapperRepresentation{
		ID:                     ptr(mapperID),
		Name:                   ptr("deviceId"),
		IdentityProviderAlias:  ptr(idpAlias),
		IdentityProviderMapper: ptr("ct-saml-in-memory-attribute-idp-mapper"),
		Config: map[string]string{
			"syncMode":       "FORCE",
			"auth.note.name": "deviceId",
			"type":           "STRING",
			"attribute.name": "deviceId",
		},
	}
}

func createTestComponent() kc.ComponentRepresentation {
	config := map[string][]string{
		compConfigName: {
			"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.1.0/24\\\"}\",\"key\":\"0123456789abcdef0123456789abcdef\"}]",
		},
	}

	return kc.ComponentRepresentation{
		Config:       config,
		ID:           ptr(compID),
		ParentID:     ptr(realmName),
		ProviderID:   ptr(compProviderID),
		ProviderType: ptr(compProviderType),
	}
}

func createTestUpdatedComponent(comp kc.ComponentRepresentation) kc.ComponentRepresentation {
	comp.Config[compConfigName] = []string{
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.1.0/24\\\"}\",\"key\":\"0123456789abcdef0123456789abcdef\"}]",
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.67.0/24\\\"}\",\"key\":\"0123456789abcdef0123456789abcdee\"}]",
	}
	return comp
}

func createTestKcFedIdentities() []kc.FederatedIdentityRepresentation {
	kcFedIdentity1 := kc.FederatedIdentityRepresentation{
		UserID:           ptr(fedUserID1),
		UserName:         ptr(fedUsername1),
		IdentityProvider: ptr(fedProvider1),
	}
	kcFedIdentity2 := kc.FederatedIdentityRepresentation{
		UserID:           ptr(fedUserID2),
		UserName:         ptr(fedUsername2),
		IdentityProvider: ptr(fedProvider2),
	}
	return []kc.FederatedIdentityRepresentation{kcFedIdentity1, kcFedIdentity2}
}

func createTestAPIFedIdentities() []api.FederatedIdentityRepresentation {
	apiFedIdentity1 := api.FederatedIdentityRepresentation{
		UserID:           ptr(fedUserID1),
		Username:         ptr(fedUsername1),
		IdentityProvider: ptr(fedProvider1),
	}
	apiFedIdentity2 := api.FederatedIdentityRepresentation{
		UserID:           ptr(fedUserID2),
		Username:         ptr(fedUsername2),
		IdentityProvider: ptr(fedProvider2),
	}
	return []api.FederatedIdentityRepresentation{apiFedIdentity1, apiFedIdentity2}
}

func TestOverrideKeycloakError(t *testing.T) {
	var notAKeycloakError = errors.New("not a keycloak error")

	assert.NoError(t, overrideKeycloakError(nil, "idp"))
	assert.Equal(t, notAKeycloakError, overrideKeycloakError(notAKeycloakError, "idp"))
	assert.IsType(t, kc.HTTPError{}, overrideKeycloakError(kc.HTTPError{HTTPStatus: http.StatusTeapot}, "idp"))
	assert.IsType(t, errorhandler.Error{}, overrideKeycloakError(kc.HTTPError{HTTPStatus: http.StatusNotFound}, "idp"))
	assert.IsType(t, kc.ClientDetailedError{}, overrideKeycloakError(kc.ClientDetailedError{HTTPStatus: http.StatusTeapot}, "idp"))
	assert.IsType(t, errorhandler.Error{}, overrideKeycloakError(kc.ClientDetailedError{HTTPStatus: http.StatusBadRequest}, "idp"))
}

func TestGetIdentityProvider(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var idpAlias = "trustid-idp"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcIdp := createTestKcIdp()
	apiIdp := createTestAPIIdp()

	t.Run("Get identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		_, err := idpComponent.GetIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Get identity provider - failed to get idp", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetIdp(technicalAccessToken, realmName, idpAlias).Return(kc.IdentityProviderRepresentation{}, anyError)

		_, err := idpComponent.GetIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Get identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetIdp(technicalAccessToken, realmName, idpAlias).Return(kcIdp, nil)

		idp, err := idpComponent.GetIdentityProvider(ctx, realmName, idpAlias)
		assert.Nil(t, err)
		assert.Equal(t, apiIdp, idp)
	})
}

func TestCreateIdentityProvider(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	emptySettings := api.HrdSettingModel{}
	settings := api.HrdSettingModel{
		IPRangesList: ptr("192.168.0.1/24,127.0.0.1/8"),
		Priority:     0,
	}

	kcIdp := createTestKcIdp()
	apiIdp := createTestAPIIdp()
	apiIdp.HrdSettings = &settings

	providerType := compProviderType
	comp := createTestComponent()
	comps := []kc.ComponentRepresentation{comp}

	updatedComp := createTestUpdatedComponent(comp)
	additionalParams := []any{"type", compProviderType}

	t.Run("Create identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - failed to create idp", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - GetComponents failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	// HRD component already exists
	t.Run("Create identity provider - GetComponentEntry failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - UpdateComponentEntry failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(nil)
		mocks.hrdTool.EXPECT().UpdateComponentEntry(&comp, idpAlias, settings).Return(anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - UpdateComponent failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(nil)
		mocks.hrdTool.EXPECT().UpdateComponentEntry(&comp, idpAlias, settings).Return(nil)
		mocks.keycloakIdpClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, *updatedComp.ID, updatedComp).Return(anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	// HRD component does not exist yet
	t.Run("Create identity provider - InitializeComponent failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, nil)
		mocks.hrdTool.EXPECT().InitializeComponent(realmName, idpAlias, apiIdp.HrdSettings).Return(kc.ComponentRepresentation{}, anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - CreateComponent failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, nil)
		mocks.hrdTool.EXPECT().InitializeComponent(realmName, idpAlias, apiIdp.HrdSettings).Return(comp, nil)
		mocks.keycloakIdpClient.EXPECT().CreateComponent(technicalAccessToken, realmName, comp).Return(anyError)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, nil)
		mocks.hrdTool.EXPECT().InitializeComponent(realmName, idpAlias, apiIdp.HrdSettings).Return(comp, nil)
		mocks.keycloakIdpClient.EXPECT().CreateComponent(technicalAccessToken, realmName, comp).Return(nil)

		err := idpComponent.CreateIdentityProvider(ctx, realmName, apiIdp)
		assert.Nil(t, err)
	})
}

func TestUpdateIdentityProvider(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	emptySettings := api.HrdSettingModel{}
	settings := api.HrdSettingModel{
		IPRangesList: ptr("192.168.0.1/24,127.0.0.1/8"),
		Priority:     0,
	}

	kcIdp := createTestKcIdp()
	apiIdp := createTestAPIIdp()
	apiIdp.HrdSettings = &settings

	providerType := compProviderType
	comp := createTestComponent()
	comps := []kc.ComponentRepresentation{comp}

	updatedComp := comp
	updatedComp.Config[compConfigName] = []string{
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.0.1/24,127.0.0.1/8\\\"}\",\"key\":\"0123456789abcdef0123456789abcdef\"}]",
	}

	additionalParams := []any{"type", compProviderType}

	t.Run("Update identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider - failed to update idp", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider - GetComponents failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	// Here we assume the HRD component already exists
	t.Run("Update identity provider - GetComponentEntry failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider - UpdateComponentEntry failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(nil)
		mocks.hrdTool.EXPECT().UpdateComponentEntry(&comp, idpAlias, settings).Return(anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider - UpdateComponent failed", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(nil)
		mocks.hrdTool.EXPECT().UpdateComponentEntry(&comp, idpAlias, settings).Return(nil)
		mocks.keycloakIdpClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, *updatedComp.ID, updatedComp).Return(anyError)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(providerType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().GetComponentEntry(&comp, idpAlias, &emptySettings).Return(nil)
		mocks.hrdTool.EXPECT().UpdateComponentEntry(&comp, idpAlias, settings).Return(nil)
		mocks.keycloakIdpClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, *updatedComp.ID, updatedComp).Return(nil)

		err := idpComponent.UpdateIdentityProvider(ctx, realmName, idpAlias, apiIdp)
		assert.Nil(t, err)
	})
}

func TestDeleteIdentityProvider(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	comp := createTestComponent()
	comps := []kc.ComponentRepresentation{comp}
	updatedComp := createTestUpdatedComponent(comp)
	additionalParams := []any{"type", compProviderType}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Delete identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to delete idp", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to get components", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(compProviderType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return([]kc.ComponentRepresentation{}, anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to delete component entry", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(compProviderType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().DeleteComponentEntry(&comp, idpAlias).Return(false, anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to update component", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(compProviderType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().DeleteComponentEntry(&comp, idpAlias).Return(true, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, *updatedComp.ID, updatedComp).Return(anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(nil)
		mocks.hrdTool.EXPECT().GetProviderType().Return(compProviderType)
		mocks.keycloakIdpClient.EXPECT().GetComponents(technicalAccessToken, realmName, additionalParams...).Return(comps, nil)
		mocks.hrdTool.EXPECT().FindComponent(comps).Return(&comp)
		mocks.hrdTool.EXPECT().DeleteComponentEntry(&comp, idpAlias).Return(true, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, *updatedComp.ID, updatedComp).Return(nil)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.Nil(t, err)
	})
}

func TestGetIdentityProviderMappers(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var idpAlias = "trustid-idp"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcMapper := createTestKcIdpMapper()
	apiMapper := createTestAPIIdpMapper()

	t.Run("Get identity provider mappers - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		_, err := idpComponent.GetIdentityProviderMappers(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Get identity provider mappers - failed to get mappers", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetIdpMappers(technicalAccessToken, realmName, idpAlias).Return([]kc.IdentityProviderMapperRepresentation{}, anyError)

		_, err := idpComponent.GetIdentityProviderMappers(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Get identity provider mappers - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetIdpMappers(technicalAccessToken, realmName, idpAlias).Return([]kc.IdentityProviderMapperRepresentation{kcMapper}, nil)

		mappers, err := idpComponent.GetIdentityProviderMappers(ctx, realmName, idpAlias)
		assert.Nil(t, err)
		assert.Len(t, mappers, 1)
		assert.Equal(t, apiMapper, mappers[0])
	})
}

func TestCreateIdentityProviderMapper(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcMapper := createTestKcIdpMapper()
	apiMapper := createTestAPIIdpMapper()

	t.Run("Create identity provider mapper - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.CreateIdentityProviderMapper(ctx, realmName, idpAlias, apiMapper)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider mapper - failed to create mapper", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdpMapper(technicalAccessToken, realmName, idpAlias, kcMapper).Return(anyError)

		err := idpComponent.CreateIdentityProviderMapper(ctx, realmName, idpAlias, apiMapper)
		assert.NotNil(t, err)
	})

	t.Run("Create identity provider mapper - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdpMapper(technicalAccessToken, realmName, idpAlias, kcMapper).Return(nil)

		err := idpComponent.CreateIdentityProviderMapper(ctx, realmName, idpAlias, apiMapper)
		assert.Nil(t, err)
	})
}

func TestUpdateIdentityProviderMapper(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcMapper := createTestKcIdpMapper()
	apiMapper := createTestAPIIdpMapper()

	t.Run("Update identity provider mapper - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.UpdateIdentityProviderMapper(ctx, realmName, idpAlias, mapperID, apiMapper)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider mapper - failed to update mapper", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdpMapper(technicalAccessToken, realmName, idpAlias, mapperID, kcMapper).Return(anyError)

		err := idpComponent.UpdateIdentityProviderMapper(ctx, realmName, idpAlias, mapperID, apiMapper)
		assert.NotNil(t, err)
	})

	t.Run("Update identity provider mapper - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdpMapper(technicalAccessToken, realmName, idpAlias, mapperID, kcMapper).Return(nil)

		err := idpComponent.UpdateIdentityProviderMapper(ctx, realmName, idpAlias, mapperID, apiMapper)
		assert.Nil(t, err)
	})
}

func TestDeleteIdentityProviderMapper(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var idpComponent = mocks.createComponent()

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Delete identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.DeleteIdentityProviderMapper(ctx, realmName, idpAlias, mapperID)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to delete idp", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdpMapper(technicalAccessToken, realmName, idpAlias, mapperID).Return(anyError)

		err := idpComponent.DeleteIdentityProviderMapper(ctx, realmName, idpAlias, mapperID)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdpMapper(technicalAccessToken, realmName, idpAlias, mapperID).Return(nil)

		err := idpComponent.DeleteIdentityProviderMapper(ctx, realmName, idpAlias, mapperID)
		assert.Nil(t, err)
	})
}

func TestDeleteUser(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		idpComponent = mocks.createComponent()
		userID       = "user-id"
		groupName    = "the-group"
		anyError     = errors.New("any error")
		ctx          = context.TODO()
	)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)
		err := idpComponent.DeleteUser(ctx, realmName, userID, nil)
		assert.Error(t, err)
	})
	t.Run("Failed to check group", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return(nil, anyError)
		err := idpComponent.DeleteUser(ctx, realmName, userID, &groupName)
		assert.Error(t, err)
	})
	t.Run("Failed to delete user", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(anyError)
		err := idpComponent.DeleteUser(ctx, realmName, userID, nil)
		assert.Error(t, err)
	})
	t.Run("Failed to delete user", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteUser(accessToken, realmName, userID).Return(nil)
		err := idpComponent.DeleteUser(ctx, realmName, userID, nil)
		assert.NoError(t, err)
	})
}

func TestCheckUserIsInGroup(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		idpComponent = mocks.createComponent()
		userID       = "user-id"
		group1       = kc.GroupRepresentation{ID: ptr("group-id-1"), Name: ptr("group #1")}
		group2       = kc.GroupRepresentation{ID: ptr("group-id-2"), Name: ptr("group #2")}
		group3       = kc.GroupRepresentation{ID: ptr("group-id-3"), Name: ptr("group #3")}
		groupName    = *group2.Name
		anyError     = errors.New("any error")
		ctx          = context.TODO()
	)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Fails to get groups", func(t *testing.T) {
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return(nil, anyError)
		err := idpComponent.checkUserIsInGroup(ctx, accessToken, realmName, userID, groupName)
		assert.Error(t, err)
	})
	t.Run("GetGroups returns a result without the expected group", func(t *testing.T) {
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group1, group3}, nil)
		err := idpComponent.checkUserIsInGroup(ctx, accessToken, realmName, userID, groupName)
		assert.Error(t, err)
	})
	t.Run("Fails to GetGroupsOfUser", func(t *testing.T) {
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group1, group2, group3}, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return(nil, anyError)
		err := idpComponent.checkUserIsInGroup(ctx, accessToken, realmName, userID, groupName)
		assert.Error(t, err)
	})
	t.Run("User is not in the expected group", func(t *testing.T) {
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group1, group2, group3}, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{group3}, nil)
		err := idpComponent.checkUserIsInGroup(ctx, accessToken, realmName, userID, groupName)
		assert.Error(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group1, group2, group3}, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{group2}, nil)
		err := idpComponent.checkUserIsInGroup(ctx, accessToken, realmName, userID, groupName)
		assert.NoError(t, err)
	})
}

func TestGetUsersWithAttribute(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		idpComponent   = mocks.createComponent()
		group          = kc.GroupRepresentation{ID: ptr("the-group-id"), Name: ptr("the-group-name")}
		kcUser         = kc.UserRepresentation{ID: ptr("the-user-id"), Username: ptr("the-username")}
		kcSearchResult = kc.UsersPageRepresentation{Count: ptrInt(2), Users: []kc.UserRepresentation{kcUser, kcUser}}
		anyError       = errors.New("any error")
		ctx            = context.TODO()
	)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Fails to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)
		_, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{}, nil)
		assert.Error(t, err)
	})

	t.Run("Fails to check group", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return(nil, anyError)
		_, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{}, nil)
		assert.Error(t, err)
	})

	t.Run("Fails to search for users", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group}, nil)
		mocks.keycloakIdpClient.EXPECT().GetUsers(accessToken, "master", realmName, "groupId", *group.ID).Return(kcSearchResult, anyError)
		_, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{}, nil)
		assert.Error(t, err)
	})

	t.Run("UserPage count is 0 even if kcUser is not empty", func(t *testing.T) {
		var emptySearchResult = kc.UsersPageRepresentation{Count: ptrInt(0), Users: []kc.UserRepresentation{kcUser, kcUser}}
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group}, nil)
		mocks.keycloakIdpClient.EXPECT().GetUsers(accessToken, "master", realmName, "groupId", *group.ID).Return(emptySearchResult, nil)
		res, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{}, nil)
		assert.NoError(t, err)
		assert.Len(t, res, 0)
	})

	t.Run("Success without role", func(t *testing.T) {
		var (
			key1   = "the-key"
			value1 = "the-value"
			key2   = "another-key"
			value2 = "another-value"
			query1 = fmt.Sprintf("%s:%s %s:%s", key1, value1, key2, value2)
			query2 = fmt.Sprintf("%s:%s %s:%s", key2, value2, key1, value1)
		)
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group}, nil)
		mocks.keycloakIdpClient.EXPECT().GetUsers(accessToken, "master", realmName, gomock.Any()).DoAndReturn(func(_, _, _ any, args ...any) (kc.UsersPageRepresentation, error) {
			querySearch := args[3].(string)
			if querySearch != query1 && querySearch != query2 {
				t.Errorf("Expected query to be '%s' or '%s', but got '%s'", query1, query2, querySearch)
			}
			return kcSearchResult, nil
		})
		res, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{key1: value1, key2: value2}, ptrBool(false))
		assert.NoError(t, err)
		assert.Len(t, res, 2)
	})

	t.Run("Can't get roles", func(t *testing.T) {
		kcSearchResult = kc.UsersPageRepresentation{Count: ptrInt(1), Users: []kc.UserRepresentation{kcUser}}
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group}, nil)
		mocks.keycloakIdpClient.EXPECT().GetUsers(accessToken, "master", realmName, gomock.Any()).Return(kcSearchResult, nil)
		mocks.keycloakIdpClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, *kcSearchResult.Users[0].ID).Return(nil, anyError)
		_, err := idpComponent.GetUsersWithAttribute(ctx, realmName, kcUser.Username, group.Name, map[string]string{}, ptrBool(true))
		assert.Error(t, err)
	})

	t.Run("Success with roles", func(t *testing.T) {
		kcSearchResult = kc.UsersPageRepresentation{Count: ptrInt(1), Users: []kc.UserRepresentation{kcUser}}
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetGroups(accessToken, realmName).Return([]kc.GroupRepresentation{group}, nil)
		mocks.keycloakIdpClient.EXPECT().GetUsers(accessToken, "master", realmName, gomock.Any()).Return(kcSearchResult, nil)
		mocks.keycloakIdpClient.EXPECT().GetRealmLevelRoleMappings(accessToken, realmName, *kcSearchResult.Users[0].ID).Return([]kc.RoleRepresentation{{ID: ptr("role-id-1"), Name: ptr("role #1")}, {ID: ptr("role-id-2"), Name: ptr("role #2")}}, nil)
		res, err := idpComponent.GetUsersWithAttribute(ctx, realmName, nil, group.Name, map[string]string{}, ptrBool(true))
		assert.NoError(t, err)
		assert.Len(t, res, 1)
		assert.Len(t, res[0].RealmRoles, 2)
	})
}

func TestAddDeleteUserAttributes(t *testing.T) {
	var mocks = createMocks(t)
	defer mocks.finish()

	var (
		userID       = "the-user-id"
		attribKey    = "the-attribute-key"
		attribValue  = "the-attribute-value"
		idpComponent = mocks.createComponentWithAllowedAttributes(realmName, []string{attribKey})
		anyError     = errors.New("any error")
		ctx          = context.TODO()
	)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Fails to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)
		err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
		assert.Error(t, err)
	})
	t.Run("Fails to get user", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{}, anyError)
		err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
		assert.Error(t, err)
	})
	t.Run("Fails to update user", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: nil}, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(anyError)
		err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
		assert.Error(t, err)
	})

	t.Run("Add attribute", func(t *testing.T) {
		t.Run("Success adding first attribute", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: nil}, nil)
			mocks.keycloakIdpClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
			err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
			assert.NoError(t, err)
		})
		t.Run("Success adding not yet existing attribute", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: &kc.Attributes{}}, nil)
			mocks.keycloakIdpClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
			err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
			assert.NoError(t, err)
		})
		t.Run("Success adding existing attribute with different value", func(t *testing.T) {
			kcUser := kc.UserRepresentation{Attributes: &kc.Attributes{kc.AttributeKey(attribKey): []string{"some-other-value"}}}
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
			mocks.keycloakIdpClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
			err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
			assert.NoError(t, err)
		})
		t.Run("Success when attribute is already set with expected value", func(t *testing.T) {
			kcUser := kc.UserRepresentation{Attributes: &kc.Attributes{kc.AttributeKey(attribKey): []string{attribValue}}}
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
			err := idpComponent.AddUserAttributes(ctx, realmName, userID, map[string][]string{attribKey: {attribValue}})
			assert.NoError(t, err)
		})
	})

	t.Run("Delete attribute", func(t *testing.T) {
		t.Run("Success with nil attributes", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: nil}, nil)
			err := idpComponent.DeleteUserAttributes(ctx, realmName, userID, []string{attribKey})
			assert.NoError(t, err)
		})
		t.Run("Success with empty attributes", func(t *testing.T) {
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kc.UserRepresentation{Attributes: &kc.Attributes{}}, nil)
			err := idpComponent.DeleteUserAttributes(ctx, realmName, userID, []string{attribKey})
			assert.NoError(t, err)
		})
		t.Run("Success with existing empty attribute", func(t *testing.T) {
			kcUser := kc.UserRepresentation{Attributes: &kc.Attributes{kc.AttributeKey(attribKey): []string{""}}}
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
			err := idpComponent.DeleteUserAttributes(ctx, realmName, userID, []string{attribKey})
			assert.NoError(t, err)
		})
		t.Run("Success with existing non-empty attribute", func(t *testing.T) {
			kcUser := kc.UserRepresentation{Attributes: &kc.Attributes{kc.AttributeKey(attribKey): []string{attribValue}}}
			mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
			mocks.keycloakIdpClient.EXPECT().GetUser(accessToken, realmName, userID).Return(kcUser, nil)
			mocks.keycloakIdpClient.EXPECT().UpdateUser(accessToken, realmName, userID, gomock.Any()).Return(nil)
			err := idpComponent.DeleteUserAttributes(ctx, realmName, userID, []string{attribKey})
			assert.NoError(t, err)
		})
	})
}

func TestGetUserFederatedIdentities(t *testing.T) {
	mocks := createMocks(t)
	defer mocks.finish()

	var (
		idpComponent = mocks.createComponent()
		userID       = "user-id-123"
		anyError     = errors.New("any error")
		ctx          = context.TODO()
	)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcFedIdentities := createTestKcFedIdentities()
	expectedResult := createTestAPIFedIdentities()

	t.Run("Failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		_, err := idpComponent.GetUserFederatedIdentities(ctx, realmName, userID)
		assert.Error(t, err)
	})

	t.Run("Failed to get federated identities", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return(nil, anyError)

		_, err := idpComponent.GetUserFederatedIdentities(ctx, realmName, userID)
		assert.Error(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(accessToken, nil)
		mocks.keycloakIdpClient.EXPECT().GetFederatedIdentities(accessToken, realmName, userID).Return(kcFedIdentities, nil)

		res, err := idpComponent.GetUserFederatedIdentities(ctx, realmName, userID)
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedResult, res)
	})
}
