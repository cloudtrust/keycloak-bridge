// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/common-service/v2/security (interfaces: KeycloakClient)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/kc-auth.go -package=mock -mock_names=KeycloakClient=KcClientAuth github.com/cloudtrust/common-service/v2/security KeycloakClient
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// KcClientAuth is a mock of KeycloakClient interface.
type KcClientAuth struct {
	ctrl     *gomock.Controller
	recorder *KcClientAuthMockRecorder
	isgomock struct{}
}

// KcClientAuthMockRecorder is the mock recorder for KcClientAuth.
type KcClientAuthMockRecorder struct {
	mock *KcClientAuth
}

// NewKcClientAuth creates a new mock instance.
func NewKcClientAuth(ctrl *gomock.Controller) *KcClientAuth {
	mock := &KcClientAuth{ctrl: ctrl}
	mock.recorder = &KcClientAuthMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *KcClientAuth) EXPECT() *KcClientAuthMockRecorder {
	return m.recorder
}

// GetGroupName mocks base method.
func (m *KcClientAuth) GetGroupName(ctx context.Context, accessToken, realmName, groupID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupName", ctx, accessToken, realmName, groupID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupName indicates an expected call of GetGroupName.
func (mr *KcClientAuthMockRecorder) GetGroupName(ctx, accessToken, realmName, groupID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupName", reflect.TypeOf((*KcClientAuth)(nil).GetGroupName), ctx, accessToken, realmName, groupID)
}

// GetGroupNamesOfUser mocks base method.
func (m *KcClientAuth) GetGroupNamesOfUser(ctx context.Context, accessToken, realmName, userID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupNamesOfUser", ctx, accessToken, realmName, userID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupNamesOfUser indicates an expected call of GetGroupNamesOfUser.
func (mr *KcClientAuthMockRecorder) GetGroupNamesOfUser(ctx, accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupNamesOfUser", reflect.TypeOf((*KcClientAuth)(nil).GetGroupNamesOfUser), ctx, accessToken, realmName, userID)
}