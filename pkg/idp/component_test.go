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
	logger            *mock.Logger
}

func createMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakIdpClient: mock.NewKeycloakIdpClient(mockCtrl),
		tokenProvider:     mock.NewOidcTokenProvider(mockCtrl),
		logger:            mock.NewLogger(mockCtrl),
	}
}

const (
	idpAlias = "testIDP"
)

func createComponent(mocks componentMocks) Component {
	return NewComponent(mocks.keycloakIdpClient, mocks.tokenProvider, mocks.logger)
}

func ptrBool(value bool) *bool {
	return &value
}

func testKcIdp() kc.IdentityProviderRepresentation {
	return kc.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  ptrBool(false),
		Alias:                     ptr(idpAlias),
		AuthenticateByDefault:     ptrBool(false),
		Config:                    &map[string]interface{}{},
		DisplayName:               ptr("TEST"),
		Enabled:                   ptrBool(false),
		FirstBrokerLoginFlowAlias: ptr("first broker login"),
		InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  ptrBool(false),
		PostBrokerLoginFlowAlias:  ptr("post broker login"),
		ProviderID:                ptr("oidc"),
		StoreToken:                ptrBool(false),
		TrustEmail:                ptrBool(false),
	}
}

func testApiIdp() api.IdentityProviderRepresentation {
	return api.IdentityProviderRepresentation{
		AddReadTokenRoleOnCreate:  ptrBool(false),
		Alias:                     ptr(idpAlias),
		AuthenticateByDefault:     ptrBool(false),
		Config:                    &map[string]interface{}{},
		DisplayName:               ptr("TEST"),
		Enabled:                   ptrBool(false),
		FirstBrokerLoginFlowAlias: ptr("first broker login"),
		InternalID:                ptr("0da3e7b1-6a99-4f73-92aa-86be96f4c2c5"),
		LinkOnly:                  ptrBool(false),
		PostBrokerLoginFlowAlias:  ptr("post broker login"),
		ProviderID:                ptr("oidc"),
		StoreToken:                ptrBool(false),
		TrustEmail:                ptrBool(false),
	}
}

func TestGetIdentityProvider(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var idpComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var realmName = "test"
	var idpAlias = "trustid-idp"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcIdp := testKcIdp()
	apiIdp := testApiIdp()

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
	var realmName = "test"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcIdp := testKcIdp()
	apiIdp := testApiIdp()

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

	t.Run("Create identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().CreateIdp(technicalAccessToken, realmName, kcIdp).Return(nil)

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
	var realmName = "test"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcIdp := testKcIdp()
	apiIdp := testApiIdp()

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

	t.Run("Update identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().UpdateIdp(technicalAccessToken, realmName, idpAlias, kcIdp).Return(nil)

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
	var realmName = "test"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	t.Run("Delete identity provider - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.NotNil(t, err)
	})

	t.Run("Delete identity provider - failed to get idp", func(t *testing.T) {
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

	t.Run("Delete identity provider - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakIdpClient.EXPECT().DeleteIdp(technicalAccessToken, realmName, idpAlias).Return(nil)

		err := idpComponent.DeleteIdentityProvider(ctx, realmName, idpAlias)
		assert.Nil(t, err)
	})
}
