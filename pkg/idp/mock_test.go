package idp

import (
	"encoding/json"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/keycloak-bridge/pkg/idp/mock"
	"github.com/go-kit/kit/endpoint"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/keycloak_idp_client.go -package=mock -mock_names=KeycloakIdpClient=KeycloakIdpClient,Component=Component github.com/cloudtrust/keycloak-bridge/pkg/idp KeycloakIdpClient,Component
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth,AuthorizationDBReader=AuthorizationDBReader,AuthorizationManager=AuthorizationManager github.com/cloudtrust/common-service/v2/security KeycloakClient,AuthorizationDBReader,AuthorizationManager
//go:generate mockgen --build_flags=--mod=mod -destination=./mock/kc-oidc.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider,ComponentTool=ComponentTool github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider,ComponentTool

func ptr(value string) *string {
	return &value
}

func toJSON(data any) string {
	bytes, _ := json.Marshal(data)
	return string(bytes)
}

type componentMocks struct {
	mockCtrl          *gomock.Controller
	keycloakIdpClient *mock.KeycloakIdpClient
	tokenProvider     *mock.OidcTokenProvider
	hrdTool           *mock.ComponentTool
	component         *mock.Component
	logger            *mock.Logger
}

func createMocks(t *testing.T) *componentMocks {
	mockCtrl := gomock.NewController(t)
	return &componentMocks{
		mockCtrl:          mockCtrl,
		keycloakIdpClient: mock.NewKeycloakIdpClient(mockCtrl),
		tokenProvider:     mock.NewOidcTokenProvider(mockCtrl),
		hrdTool:           mock.NewComponentTool(mockCtrl),
		component:         mock.NewComponent(mockCtrl),
		logger:            mock.NewLogger(mockCtrl),
	}
}

func (m *componentMocks) finish() {
	m.mockCtrl.Finish()
}

func (m *componentMocks) createComponent() *component {
	return NewComponent(m.keycloakIdpClient, m.tokenProvider, m.hrdTool, m.logger).(*component)
}

func (m *componentMocks) newEndpoints() Endpoints {
	return NewEndpoints(m.component, func(e cs.Endpoint, name string) endpoint.Endpoint {
		return endpoint.Endpoint(e)
	})
}
