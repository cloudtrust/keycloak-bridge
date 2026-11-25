package misc

import (
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/keycloak-bridge/pkg/misc/mock"
	"github.com/go-kit/kit/endpoint"
	"go.uber.org/mock/gomock"
)

//go:generate mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/pkg/misc Component,KeycloakClient

type mockMisc struct {
	mockCtrl  *gomock.Controller
	component *mock.Component
	kcClient  *mock.KeycloakClient
	logger    log.Logger
}

func newMiscMocks(t *testing.T) *mockMisc {
	var mockCtrl = gomock.NewController(t)
	return &mockMisc{
		mockCtrl:  mockCtrl,
		component: mock.NewComponent(mockCtrl),
		kcClient:  mock.NewKeycloakClient(mockCtrl),
		logger:    log.NewNopLogger(),
	}
}

func (m *mockMisc) finish() {
	m.mockCtrl.Finish()
}

func (m *mockMisc) newEndpoints() Endpoints {
	return NewEndpoints(m.component, func(e cs.Endpoint, name string) endpoint.Endpoint {
		return endpoint.Endpoint(e)
	})
}

func (m *mockMisc) createComponent() Component {
	return NewComponent(m.kcClient, m.logger)
}
