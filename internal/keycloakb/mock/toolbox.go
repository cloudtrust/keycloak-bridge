// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-client/v2/toolbox (interfaces: OidcTokenProvider)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/toolbox.go -package=mock -mock_names=OidcTokenProvider=OidcTokenProvider github.com/cloudtrust/keycloak-client/v2/toolbox OidcTokenProvider
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// OidcTokenProvider is a mock of OidcTokenProvider interface.
type OidcTokenProvider struct {
	ctrl     *gomock.Controller
	recorder *OidcTokenProviderMockRecorder
	isgomock struct{}
}

// OidcTokenProviderMockRecorder is the mock recorder for OidcTokenProvider.
type OidcTokenProviderMockRecorder struct {
	mock *OidcTokenProvider
}

// NewOidcTokenProvider creates a new mock instance.
func NewOidcTokenProvider(ctrl *gomock.Controller) *OidcTokenProvider {
	mock := &OidcTokenProvider{ctrl: ctrl}
	mock.recorder = &OidcTokenProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *OidcTokenProvider) EXPECT() *OidcTokenProviderMockRecorder {
	return m.recorder
}

// ProvideToken mocks base method.
func (m *OidcTokenProvider) ProvideToken(ctx context.Context) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProvideToken", ctx)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ProvideToken indicates an expected call of ProvideToken.
func (mr *OidcTokenProviderMockRecorder) ProvideToken(ctx any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProvideToken", reflect.TypeOf((*OidcTokenProvider)(nil).ProvideToken), ctx)
}

// ProvideTokenForRealm mocks base method.
func (m *OidcTokenProvider) ProvideTokenForRealm(ctx context.Context, realm string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProvideTokenForRealm", ctx, realm)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ProvideTokenForRealm indicates an expected call of ProvideTokenForRealm.
func (mr *OidcTokenProviderMockRecorder) ProvideTokenForRealm(ctx, realm any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProvideTokenForRealm", reflect.TypeOf((*OidcTokenProvider)(nil).ProvideTokenForRealm), ctx, realm)
}
