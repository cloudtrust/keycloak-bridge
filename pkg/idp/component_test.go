package idp

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	api "github.com/cloudtrust/keycloak-bridge/api/idp"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakIdpClient *mock.KeycloakIdpClient
	tokenProvider     *mock.OidcTokenProvider
	hrdTool           *mock.ComponentTool
	logger            *mock.Logger
}

func createMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakIdpClient: mock.NewKeycloakIdpClient(mockCtrl),
		tokenProvider:     mock.NewOidcTokenProvider(mockCtrl),
		hrdTool:           mock.NewComponentTool(mockCtrl),
		logger:            mock.NewLogger(mockCtrl),
	}
}

const (
	realmName = "test"

	idpAlias = "testIDP"

	compID           = "5b3f0a5d-a59d-4aff-8932-aa70f2806f04"
	compProviderType = "org.keycloak.services.ui.extend.UiTabProvider"
	compProviderID   = "Home-realm discovery settings"
	compConfigName   = "hrdSettings"
)

func createComponent(mocks componentMocks) Component {
	return NewComponent(mocks.keycloakIdpClient, mocks.tokenProvider, mocks.hrdTool, mocks.logger)
}

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

func createTestApiIdp() api.IdentityProviderRepresentation {
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

func createTestComponent() kc.ComponentRepresentation {
	config := map[string][]string{
		compConfigName: {
			"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.1.0/24\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678900\"}]",
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
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.1.0/24\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678900\"}]",
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.67.0/24\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678901\"}]",
	}
	return comp
}

func TestGetIdentityProvider(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var idpComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var idpAlias = "trustid-idp"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcIdp := createTestKcIdp()
	apiIdp := createTestApiIdp()

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
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var idpComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	emptySettings := api.HrdSettingModel{}
	settings := api.HrdSettingModel{
		IPRangesList: "192.168.0.1/24,127.0.0.1/8",
	}

	kcIdp := createTestKcIdp()
	apiIdp := createTestApiIdp()
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
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var idpComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	emptySettings := api.HrdSettingModel{}
	settings := api.HrdSettingModel{
		IPRangesList: "192.168.0.1/24,127.0.0.1/8",
	}

	kcIdp := createTestKcIdp()
	apiIdp := createTestApiIdp()
	apiIdp.HrdSettings = &settings

	providerType := compProviderType
	comp := createTestComponent()
	comps := []kc.ComponentRepresentation{comp}

	updatedComp := comp
	updatedComp.Config[compConfigName] = []string{
		"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.0.1/24,127.0.0.1/8\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678900\"}]",
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
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var idpComponent = createComponent(mocks)

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
