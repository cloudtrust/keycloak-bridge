// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/pkg/validation (interfaces: Component,KeycloakClient,TokenProvider,ArchiveDBModule,ConfigurationDBModule,UserProfileCache)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/component.go -package=mock -mock_names=Component=Component,KeycloakClient=KeycloakClient,TokenProvider=TokenProvider,ArchiveDBModule=ArchiveDBModule,ConfigurationDBModule=ConfigurationDBModule,UserProfileCache=UserProfileCache github.com/cloudtrust/keycloak-bridge/pkg/validation Component,KeycloakClient,TokenProvider,ArchiveDBModule,ConfigurationDBModule,UserProfileCache
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	configuration "github.com/cloudtrust/common-service/v2/configuration"
	apivalidation "github.com/cloudtrust/keycloak-bridge/api/validation"
	dto "github.com/cloudtrust/keycloak-bridge/internal/dto"
	keycloak "github.com/cloudtrust/keycloak-client/v2"
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

// GetGroupsOfUser mocks base method.
func (m *Component) GetGroupsOfUser(ctx context.Context, realmName, userID string) ([]apivalidation.GroupRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupsOfUser", ctx, realmName, userID)
	ret0, _ := ret[0].([]apivalidation.GroupRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupsOfUser indicates an expected call of GetGroupsOfUser.
func (mr *ComponentMockRecorder) GetGroupsOfUser(ctx, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupsOfUser", reflect.TypeOf((*Component)(nil).GetGroupsOfUser), ctx, realmName, userID)
}

// GetUser mocks base method.
func (m *Component) GetUser(ctx context.Context, realmName, userID string) (apivalidation.UserRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", ctx, realmName, userID)
	ret0, _ := ret[0].(apivalidation.UserRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *ComponentMockRecorder) GetUser(ctx, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*Component)(nil).GetUser), ctx, realmName, userID)
}

// UpdateUser mocks base method.
func (m *Component) UpdateUser(ctx context.Context, realmName, userID string, user apivalidation.UserRepresentation, txnID *string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", ctx, realmName, userID, user, txnID)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *ComponentMockRecorder) UpdateUser(ctx, realmName, userID, user, txnID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*Component)(nil).UpdateUser), ctx, realmName, userID, user, txnID)
}

// UpdateUserAccreditations mocks base method.
func (m *Component) UpdateUserAccreditations(ctx context.Context, realmName, userID string, userAccreds []apivalidation.AccreditationRepresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUserAccreditations", ctx, realmName, userID, userAccreds)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUserAccreditations indicates an expected call of UpdateUserAccreditations.
func (mr *ComponentMockRecorder) UpdateUserAccreditations(ctx, realmName, userID, userAccreds any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUserAccreditations", reflect.TypeOf((*Component)(nil).UpdateUserAccreditations), ctx, realmName, userID, userAccreds)
}

// KeycloakClient is a mock of KeycloakClient interface.
type KeycloakClient struct {
	ctrl     *gomock.Controller
	recorder *KeycloakClientMockRecorder
	isgomock struct{}
}

// KeycloakClientMockRecorder is the mock recorder for KeycloakClient.
type KeycloakClientMockRecorder struct {
	mock *KeycloakClient
}

// NewKeycloakClient creates a new mock instance.
func NewKeycloakClient(ctrl *gomock.Controller) *KeycloakClient {
	mock := &KeycloakClient{ctrl: ctrl}
	mock.recorder = &KeycloakClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *KeycloakClient) EXPECT() *KeycloakClientMockRecorder {
	return m.recorder
}

// GetGroupsOfUser mocks base method.
func (m *KeycloakClient) GetGroupsOfUser(accessToken, realmName, userID string) ([]keycloak.GroupRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupsOfUser", accessToken, realmName, userID)
	ret0, _ := ret[0].([]keycloak.GroupRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupsOfUser indicates an expected call of GetGroupsOfUser.
func (mr *KeycloakClientMockRecorder) GetGroupsOfUser(accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupsOfUser", reflect.TypeOf((*KeycloakClient)(nil).GetGroupsOfUser), accessToken, realmName, userID)
}

// GetRealm mocks base method.
func (m *KeycloakClient) GetRealm(accessToken, realmName string) (keycloak.RealmRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRealm", accessToken, realmName)
	ret0, _ := ret[0].(keycloak.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealm indicates an expected call of GetRealm.
func (mr *KeycloakClientMockRecorder) GetRealm(accessToken, realmName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealm", reflect.TypeOf((*KeycloakClient)(nil).GetRealm), accessToken, realmName)
}

// GetUser mocks base method.
func (m *KeycloakClient) GetUser(accessToken, realmName, userID string) (keycloak.UserRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", accessToken, realmName, userID)
	ret0, _ := ret[0].(keycloak.UserRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *KeycloakClientMockRecorder) GetUser(accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*KeycloakClient)(nil).GetUser), accessToken, realmName, userID)
}

// UpdateUser mocks base method.
func (m *KeycloakClient) UpdateUser(accessToken, realmName, userID string, user keycloak.UserRepresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", accessToken, realmName, userID, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *KeycloakClientMockRecorder) UpdateUser(accessToken, realmName, userID, user any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*KeycloakClient)(nil).UpdateUser), accessToken, realmName, userID, user)
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

// ArchiveDBModule is a mock of ArchiveDBModule interface.
type ArchiveDBModule struct {
	ctrl     *gomock.Controller
	recorder *ArchiveDBModuleMockRecorder
	isgomock struct{}
}

// ArchiveDBModuleMockRecorder is the mock recorder for ArchiveDBModule.
type ArchiveDBModuleMockRecorder struct {
	mock *ArchiveDBModule
}

// NewArchiveDBModule creates a new mock instance.
func NewArchiveDBModule(ctrl *gomock.Controller) *ArchiveDBModule {
	mock := &ArchiveDBModule{ctrl: ctrl}
	mock.recorder = &ArchiveDBModuleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *ArchiveDBModule) EXPECT() *ArchiveDBModuleMockRecorder {
	return m.recorder
}

// StoreUserDetails mocks base method.
func (m *ArchiveDBModule) StoreUserDetails(ctx context.Context, realm string, user dto.ArchiveUserRepresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreUserDetails", ctx, realm, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreUserDetails indicates an expected call of StoreUserDetails.
func (mr *ArchiveDBModuleMockRecorder) StoreUserDetails(ctx, realm, user any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreUserDetails", reflect.TypeOf((*ArchiveDBModule)(nil).StoreUserDetails), ctx, realm, user)
}

// ConfigurationDBModule is a mock of ConfigurationDBModule interface.
type ConfigurationDBModule struct {
	ctrl     *gomock.Controller
	recorder *ConfigurationDBModuleMockRecorder
	isgomock struct{}
}

// ConfigurationDBModuleMockRecorder is the mock recorder for ConfigurationDBModule.
type ConfigurationDBModuleMockRecorder struct {
	mock *ConfigurationDBModule
}

// NewConfigurationDBModule creates a new mock instance.
func NewConfigurationDBModule(ctrl *gomock.Controller) *ConfigurationDBModule {
	mock := &ConfigurationDBModule{ctrl: ctrl}
	mock.recorder = &ConfigurationDBModuleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *ConfigurationDBModule) EXPECT() *ConfigurationDBModuleMockRecorder {
	return m.recorder
}

// GetAdminConfiguration mocks base method.
func (m *ConfigurationDBModule) GetAdminConfiguration(arg0 context.Context, arg1 string) (configuration.RealmAdminConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAdminConfiguration", arg0, arg1)
	ret0, _ := ret[0].(configuration.RealmAdminConfiguration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAdminConfiguration indicates an expected call of GetAdminConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) GetAdminConfiguration(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAdminConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).GetAdminConfiguration), arg0, arg1)
}

// UserProfileCache is a mock of UserProfileCache interface.
type UserProfileCache struct {
	ctrl     *gomock.Controller
	recorder *UserProfileCacheMockRecorder
	isgomock struct{}
}

// UserProfileCacheMockRecorder is the mock recorder for UserProfileCache.
type UserProfileCacheMockRecorder struct {
	mock *UserProfileCache
}

// NewUserProfileCache creates a new mock instance.
func NewUserProfileCache(ctrl *gomock.Controller) *UserProfileCache {
	mock := &UserProfileCache{ctrl: ctrl}
	mock.recorder = &UserProfileCacheMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *UserProfileCache) EXPECT() *UserProfileCacheMockRecorder {
	return m.recorder
}

// GetRealmUserProfile mocks base method.
func (m *UserProfileCache) GetRealmUserProfile(ctx context.Context, realmName string) (keycloak.UserProfileRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRealmUserProfile", ctx, realmName)
	ret0, _ := ret[0].(keycloak.UserProfileRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealmUserProfile indicates an expected call of GetRealmUserProfile.
func (mr *UserProfileCacheMockRecorder) GetRealmUserProfile(ctx, realmName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealmUserProfile", reflect.TypeOf((*UserProfileCache)(nil).GetRealmUserProfile), ctx, realmName)
}