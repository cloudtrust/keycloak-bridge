// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/pkg/mobile (interfaces: Component,TokenProvider,AccountingClient)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,TokenProvider=TokenProvider,AccountingClient=AccountingClient github.com/cloudtrust/keycloak-bridge/pkg/mobile Component,TokenProvider,AccountingClient
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	mobileapi "github.com/cloudtrust/keycloak-bridge/api/mobile"
	gomock "go.uber.org/mock/gomock"
)

// Component is a mock of Component interface.
type Component struct {
	ctrl     *gomock.Controller
	recorder *ComponentMockRecorder
	isgomock struct{}
}

// ComponentMockRecorder is the mock recorder for Component.
type ComponentMockRecorder struct {
	mock *Component
}

// NewComponent creates a new mock instance.
func NewComponent(ctrl *gomock.Controller) *Component {
	mock := &Component{ctrl: ctrl}
	mock.recorder = &ComponentMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Component) EXPECT() *ComponentMockRecorder {
	return m.recorder
}

// GetUserInformation mocks base method.
func (m *Component) GetUserInformation(ctx context.Context) (mobileapi.UserInformationRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserInformation", ctx)
	ret0, _ := ret[0].(mobileapi.UserInformationRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserInformation indicates an expected call of GetUserInformation.
func (mr *ComponentMockRecorder) GetUserInformation(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserInformation", reflect.TypeOf((*Component)(nil).GetUserInformation), ctx)
}

// TokenProvider is a mock of TokenProvider interface.
type TokenProvider struct {
	ctrl     *gomock.Controller
	recorder *TokenProviderMockRecorder
	isgomock struct{}
}

// TokenProviderMockRecorder is the mock recorder for TokenProvider.
type TokenProviderMockRecorder struct {
	mock *TokenProvider
}

// NewTokenProvider creates a new mock instance.
func NewTokenProvider(ctrl *gomock.Controller) *TokenProvider {
	mock := &TokenProvider{ctrl: ctrl}
	mock.recorder = &TokenProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *TokenProvider) EXPECT() *TokenProviderMockRecorder {
	return m.recorder
}

// ProvideToken mocks base method.
func (m *TokenProvider) ProvideToken(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProvideToken", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ProvideToken indicates an expected call of ProvideToken.
func (mr *TokenProviderMockRecorder) ProvideToken(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProvideToken", reflect.TypeOf((*TokenProvider)(nil).ProvideToken), ctx)
}

// AccountingClient is a mock of AccountingClient interface.
type AccountingClient struct {
	ctrl     *gomock.Controller
	recorder *AccountingClientMockRecorder
	isgomock struct{}
}

// AccountingClientMockRecorder is the mock recorder for AccountingClient.
type AccountingClientMockRecorder struct {
	mock *AccountingClient
}

// NewAccountingClient creates a new mock instance.
func NewAccountingClient(ctrl *gomock.Controller) *AccountingClient {
	mock := &AccountingClient{ctrl: ctrl}
	mock.recorder = &AccountingClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *AccountingClient) EXPECT() *AccountingClientMockRecorder {
	return m.recorder
}

// GetBalance mocks base method.
func (m *AccountingClient) GetBalance(ctx context.Context, realmName, userID, service string) (float64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBalance", ctx, realmName, userID, service)
	ret0, _ := ret[0].(float64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBalance indicates an expected call of GetBalance.
func (mr *AccountingClientMockRecorder) GetBalance(ctx, realmName, userID, service any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBalance", reflect.TypeOf((*AccountingClient)(nil).GetBalance), ctx, realmName, userID, service)
}
