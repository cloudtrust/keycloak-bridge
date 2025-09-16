package components

import (
	"context"
	"errors"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	api "github.com/cloudtrust/keycloak-bridge/api/components"
	"github.com/cloudtrust/keycloak-bridge/pkg/components/mock"
	kc "github.com/cloudtrust/keycloak-client/v2"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

type componentMocks struct {
	keycloakComponentClient *mock.KeycloakComponentClient
	tokenProvider           *mock.OidcTokenProvider
	logger                  *mock.Logger
}

func createMocks(mockCtrl *gomock.Controller) componentMocks {
	return componentMocks{
		keycloakComponentClient: mock.NewKeycloakComponentClient(mockCtrl),
		tokenProvider:           mock.NewOidcTokenProvider(mockCtrl),
		logger:                  mock.NewLogger(mockCtrl),
	}
}

const (
	compID           = "b5fd6854-ac8e-415b-8779-d89e6b6de3f4"
	compParentID     = "test-community"
	compProviderID   = "Home-realm discovery settings"
	compProviderType = "org.keycloak.services.ui.extend.UiTabProvider"
	compSubType      = ""
	compConfigName   = "hrdSettings"
)

func createComponent(mocks componentMocks) Component {
	return NewComponent(mocks.keycloakComponentClient, mocks.tokenProvider, mocks.logger)
}

func ptrBool(value bool) *bool {
	return &value
}

func testConfig() map[string][]string {
	return map[string][]string{
		compConfigName: {
			"[{\"value\":\"{\\\"ipRangesList\\\":\\\"192.168.67.0/24\\\"}\",\"key\":\"EXTIDP-12345678-abcd-efgh-ijkl-012345678901\"}]",
		},
	}
}

func testKcComp() kc.ComponentRepresentation {
	config := testConfig()
	return kc.ComponentRepresentation{
		Config:       &config,
		ID:           ptr(compID),
		ParentID:     ptr(compParentID),
		ProviderID:   ptr(compProviderID),
		ProviderType: ptr(compProviderType),
		SubType:      ptr(compSubType),
	}

}

func testApiComp() api.ComponentRepresentation {
	config := testConfig()
	return api.ComponentRepresentation{
		Config:       &config,
		ID:           ptr(compID),
		ParentID:     ptr(compParentID),
		ProviderID:   ptr(compProviderID),
		ProviderType: ptr(compProviderType),
		SubType:      ptr(compSubType),
	}
}

func TestGetComponents(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var compComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var realmName = "test"
	var anyError = errors.New("any error")

	var providerType = compProviderType
	var providerTypeParam = []string{"type", providerType}

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcComp := testKcComp()
	apiComp := testApiComp()

	t.Run("Get components - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		_, err := compComponent.GetComponents(ctx, realmName, &providerType)
		assert.NotNil(t, err)
	})

	t.Run("Get components - failed to get components", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().GetComponents(technicalAccessToken, realmName, providerTypeParam).Return([]kc.ComponentRepresentation{}, anyError)

		_, err := compComponent.GetComponents(ctx, realmName, &providerType)
		assert.NotNil(t, err)
	})

	t.Run("Get components - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().GetComponents(technicalAccessToken, realmName, providerTypeParam).Return([]kc.ComponentRepresentation{kcComp}, nil)

		kcComps, err := compComponent.GetComponents(ctx, realmName, &providerType)
		assert.Nil(t, err)
		assert.Equal(t, []api.ComponentRepresentation{apiComp}, kcComps)
	})
}

func TestCreateComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var compComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var realmName = "test"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcComp := testKcComp()
	apiComp := testApiComp()

	t.Run("Create component - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := compComponent.CreateComponent(ctx, realmName, apiComp)
		assert.NotNil(t, err)
	})

	t.Run("Create component - failed to create component", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().CreateComponent(technicalAccessToken, realmName, kcComp).Return(anyError)

		err := compComponent.CreateComponent(ctx, realmName, apiComp)
		assert.NotNil(t, err)
	})

	t.Run("Create component - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().CreateComponent(technicalAccessToken, realmName, kcComp).Return(nil)

		err := compComponent.CreateComponent(ctx, realmName, apiComp)
		assert.Nil(t, err)
	})
}

func TestUpdateComponent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mocks = createMocks(mockCtrl)
	var compComponent = createComponent(mocks)

	var accessToken = "TOKEN=="
	var technicalAccessToken = "abcd-1234"
	var realmName = "test"
	var anyError = errors.New("any error")

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

	kcComp := testKcComp()
	apiComp := testApiComp()

	t.Run("Update component - failed to get technical access token", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

		err := compComponent.UpdateComponent(ctx, realmName, compID, apiComp)
		assert.NotNil(t, err)
	})

	t.Run("Update component - failed to update component", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, compID, kcComp).Return(anyError)

		err := compComponent.UpdateComponent(ctx, realmName, compID, apiComp)
		assert.NotNil(t, err)
	})

	t.Run("Update component - success", func(t *testing.T) {
		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
		mocks.keycloakComponentClient.EXPECT().UpdateComponent(technicalAccessToken, realmName, compID, kcComp).Return(nil)

		err := compComponent.UpdateComponent(ctx, realmName, compID, apiComp)
		assert.Nil(t, err)
	})
}

// func TestDeleteComponent(t *testing.T) {
// 	var mockCtrl = gomock.NewController(t)
// 	defer mockCtrl.Finish()

// 	var mocks = createMocks(mockCtrl)
// 	var compComponent = createComponent(mocks)

// 	var accessToken = "TOKEN=="
// 	var technicalAccessToken = "abcd-1234"
// 	var realmName = "test"
// 	var anyError = errors.New("any error")

// 	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)

// 	mocks.logger.EXPECT().Warn(gomock.Any(), gomock.Any()).AnyTimes()

// 	t.Run("Delete component - failed to get technical access token", func(t *testing.T) {
// 		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

// 		err := compComponent.DeleteComponent(ctx, realmName, compID)
// 		assert.NotNil(t, err)
// 	})

// 	t.Run("Delete component - failed to get component", func(t *testing.T) {
// 		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return("", anyError)

// 		err := compComponent.DeleteComponent(ctx, realmName, compID)
// 		assert.NotNil(t, err)
// 	})

// 	t.Run("Delete component - failed to delete component", func(t *testing.T) {
// 		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
// 		mocks.keycloakComponentClient.EXPECT().DeleteComponent(technicalAccessToken, realmName, compID).Return(anyError)

// 		err := compComponent.DeleteComponent(ctx, realmName, compID)
// 		assert.NotNil(t, err)
// 	})

// 	t.Run("Delete component - success", func(t *testing.T) {
// 		mocks.tokenProvider.EXPECT().ProvideTokenForRealm(ctx, realmName).Return(technicalAccessToken, nil)
// 		mocks.keycloakComponentClient.EXPECT().DeleteComponent(technicalAccessToken, realmName, compID).Return(nil)

// 		err := compComponent.DeleteComponent(ctx, realmName, compID)
// 		assert.Nil(t, err)
// 	})
// }
