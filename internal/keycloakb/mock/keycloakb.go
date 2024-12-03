// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/internal/keycloakb (interfaces: ConfigurationDBModule,AccredsKeycloakClient,KeycloakClient,KeycloakForTechnicalClient,Logger,HTTPClient,OnboardingKeycloakClient,KeycloakURIProvider)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/keycloakb.go -package=mock -mock_names=ConfigurationDBModule=ConfigurationDBModule,AccredsKeycloakClient=AccredsKeycloakClient,KeycloakClient=KeycloakClient,KeycloakForTechnicalClient=KeycloakForTechnicalClient,Logger=Logger,HTTPClient=HTTPClient,OnboardingKeycloakClient=OnboardingKeycloakClient,KeycloakURIProvider=KeycloakURIProvider github.com/cloudtrust/keycloak-bridge/internal/keycloakb ConfigurationDBModule,AccredsKeycloakClient,KeycloakClient,KeycloakForTechnicalClient,Logger,HTTPClient,OnboardingKeycloakClient,KeycloakURIProvider
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	configuration "github.com/cloudtrust/common-service/v2/configuration"
	sqltypes "github.com/cloudtrust/common-service/v2/database/sqltypes"
	dto "github.com/cloudtrust/keycloak-bridge/internal/dto"
	keycloak "github.com/cloudtrust/keycloak-client/v2"
	gomock "go.uber.org/mock/gomock"
	plugin "gopkg.in/h2non/gentleman.v2/plugin"
)

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

// AuthorizationExists mocks base method.
func (m *ConfigurationDBModule) AuthorizationExists(context context.Context, realmID, groupName, targetRealm string, targetGroupName *string, actionReq string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthorizationExists", context, realmID, groupName, targetRealm, targetGroupName, actionReq)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthorizationExists indicates an expected call of AuthorizationExists.
func (mr *ConfigurationDBModuleMockRecorder) AuthorizationExists(context, realmID, groupName, targetRealm, targetGroupName, actionReq any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthorizationExists", reflect.TypeOf((*ConfigurationDBModule)(nil).AuthorizationExists), context, realmID, groupName, targetRealm, targetGroupName, actionReq)
}

// CleanAuthorizationsActionForEveryRealms mocks base method.
func (m *ConfigurationDBModule) CleanAuthorizationsActionForEveryRealms(context context.Context, realmID, groupName, actionReq string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanAuthorizationsActionForEveryRealms", context, realmID, groupName, actionReq)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanAuthorizationsActionForEveryRealms indicates an expected call of CleanAuthorizationsActionForEveryRealms.
func (mr *ConfigurationDBModuleMockRecorder) CleanAuthorizationsActionForEveryRealms(context, realmID, groupName, actionReq any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanAuthorizationsActionForEveryRealms", reflect.TypeOf((*ConfigurationDBModule)(nil).CleanAuthorizationsActionForEveryRealms), context, realmID, groupName, actionReq)
}

// CleanAuthorizationsActionForRealm mocks base method.
func (m *ConfigurationDBModule) CleanAuthorizationsActionForRealm(context context.Context, realmID, groupName, targetRealm, actionReq string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CleanAuthorizationsActionForRealm", context, realmID, groupName, targetRealm, actionReq)
	ret0, _ := ret[0].(error)
	return ret0
}

// CleanAuthorizationsActionForRealm indicates an expected call of CleanAuthorizationsActionForRealm.
func (mr *ConfigurationDBModuleMockRecorder) CleanAuthorizationsActionForRealm(context, realmID, groupName, targetRealm, actionReq any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CleanAuthorizationsActionForRealm", reflect.TypeOf((*ConfigurationDBModule)(nil).CleanAuthorizationsActionForRealm), context, realmID, groupName, targetRealm, actionReq)
}

// CreateAuthorization mocks base method.
func (m *ConfigurationDBModule) CreateAuthorization(context context.Context, authz configuration.Authorization) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthorization", context, authz)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateAuthorization indicates an expected call of CreateAuthorization.
func (mr *ConfigurationDBModuleMockRecorder) CreateAuthorization(context, authz any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthorization", reflect.TypeOf((*ConfigurationDBModule)(nil).CreateAuthorization), context, authz)
}

// DeleteAllAuthorizationsWithGroup mocks base method.
func (m *ConfigurationDBModule) DeleteAllAuthorizationsWithGroup(context context.Context, realmName, groupName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAllAuthorizationsWithGroup", context, realmName, groupName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllAuthorizationsWithGroup indicates an expected call of DeleteAllAuthorizationsWithGroup.
func (mr *ConfigurationDBModuleMockRecorder) DeleteAllAuthorizationsWithGroup(context, realmName, groupName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllAuthorizationsWithGroup", reflect.TypeOf((*ConfigurationDBModule)(nil).DeleteAllAuthorizationsWithGroup), context, realmName, groupName)
}

// DeleteAuthorization mocks base method.
func (m *ConfigurationDBModule) DeleteAuthorization(context context.Context, realmID, groupName, targetRealm string, targetGroupName *string, actionReq string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAuthorization", context, realmID, groupName, targetRealm, targetGroupName, actionReq)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAuthorization indicates an expected call of DeleteAuthorization.
func (mr *ConfigurationDBModuleMockRecorder) DeleteAuthorization(context, realmID, groupName, targetRealm, targetGroupName, actionReq any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAuthorization", reflect.TypeOf((*ConfigurationDBModule)(nil).DeleteAuthorization), context, realmID, groupName, targetRealm, targetGroupName, actionReq)
}

// DeleteBackOfficeConfiguration mocks base method.
func (m *ConfigurationDBModule) DeleteBackOfficeConfiguration(arg0 context.Context, arg1, arg2, arg3 string, arg4, arg5 *string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteBackOfficeConfiguration", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteBackOfficeConfiguration indicates an expected call of DeleteBackOfficeConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) DeleteBackOfficeConfiguration(arg0, arg1, arg2, arg3, arg4, arg5 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteBackOfficeConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).DeleteBackOfficeConfiguration), arg0, arg1, arg2, arg3, arg4, arg5)
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

// GetAuthorizations mocks base method.
func (m *ConfigurationDBModule) GetAuthorizations(context context.Context, realmID, groupName string) ([]configuration.Authorization, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthorizations", context, realmID, groupName)
	ret0, _ := ret[0].([]configuration.Authorization)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAuthorizations indicates an expected call of GetAuthorizations.
func (mr *ConfigurationDBModuleMockRecorder) GetAuthorizations(context, realmID, groupName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthorizations", reflect.TypeOf((*ConfigurationDBModule)(nil).GetAuthorizations), context, realmID, groupName)
}

// GetBackOfficeConfiguration mocks base method.
func (m *ConfigurationDBModule) GetBackOfficeConfiguration(arg0 context.Context, arg1 string, arg2 []string) (dto.BackOfficeConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBackOfficeConfiguration", arg0, arg1, arg2)
	ret0, _ := ret[0].(dto.BackOfficeConfiguration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBackOfficeConfiguration indicates an expected call of GetBackOfficeConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) GetBackOfficeConfiguration(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBackOfficeConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).GetBackOfficeConfiguration), arg0, arg1, arg2)
}

// GetConfiguration mocks base method.
func (m *ConfigurationDBModule) GetConfiguration(arg0 context.Context, arg1 string) (configuration.RealmConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConfiguration", arg0, arg1)
	ret0, _ := ret[0].(configuration.RealmConfiguration)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConfiguration indicates an expected call of GetConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) GetConfiguration(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).GetConfiguration), arg0, arg1)
}

// GetConfigurations mocks base method.
func (m *ConfigurationDBModule) GetConfigurations(arg0 context.Context, arg1 string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConfigurations", arg0, arg1)
	ret0, _ := ret[0].(configuration.RealmConfiguration)
	ret1, _ := ret[1].(configuration.RealmAdminConfiguration)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetConfigurations indicates an expected call of GetConfigurations.
func (mr *ConfigurationDBModuleMockRecorder) GetConfigurations(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConfigurations", reflect.TypeOf((*ConfigurationDBModule)(nil).GetConfigurations), arg0, arg1)
}

// InsertBackOfficeConfiguration mocks base method.
func (m *ConfigurationDBModule) InsertBackOfficeConfiguration(arg0 context.Context, arg1, arg2, arg3, arg4 string, arg5 []string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InsertBackOfficeConfiguration", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertBackOfficeConfiguration indicates an expected call of InsertBackOfficeConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) InsertBackOfficeConfiguration(arg0, arg1, arg2, arg3, arg4, arg5 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertBackOfficeConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).InsertBackOfficeConfiguration), arg0, arg1, arg2, arg3, arg4, arg5)
}

// NewTransaction mocks base method.
func (m *ConfigurationDBModule) NewTransaction(context context.Context) (sqltypes.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewTransaction", context)
	ret0, _ := ret[0].(sqltypes.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewTransaction indicates an expected call of NewTransaction.
func (mr *ConfigurationDBModuleMockRecorder) NewTransaction(context any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewTransaction", reflect.TypeOf((*ConfigurationDBModule)(nil).NewTransaction), context)
}

// StoreOrUpdateAdminConfiguration mocks base method.
func (m *ConfigurationDBModule) StoreOrUpdateAdminConfiguration(arg0 context.Context, arg1 string, arg2 configuration.RealmAdminConfiguration) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreOrUpdateAdminConfiguration", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreOrUpdateAdminConfiguration indicates an expected call of StoreOrUpdateAdminConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) StoreOrUpdateAdminConfiguration(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreOrUpdateAdminConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).StoreOrUpdateAdminConfiguration), arg0, arg1, arg2)
}

// StoreOrUpdateConfiguration mocks base method.
func (m *ConfigurationDBModule) StoreOrUpdateConfiguration(arg0 context.Context, arg1 string, arg2 configuration.RealmConfiguration) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StoreOrUpdateConfiguration", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// StoreOrUpdateConfiguration indicates an expected call of StoreOrUpdateConfiguration.
func (mr *ConfigurationDBModuleMockRecorder) StoreOrUpdateConfiguration(arg0, arg1, arg2 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StoreOrUpdateConfiguration", reflect.TypeOf((*ConfigurationDBModule)(nil).StoreOrUpdateConfiguration), arg0, arg1, arg2)
}

// AccredsKeycloakClient is a mock of AccredsKeycloakClient interface.
type AccredsKeycloakClient struct {
	ctrl     *gomock.Controller
	recorder *AccredsKeycloakClientMockRecorder
	isgomock struct{}
}

// AccredsKeycloakClientMockRecorder is the mock recorder for AccredsKeycloakClient.
type AccredsKeycloakClientMockRecorder struct {
	mock *AccredsKeycloakClient
}

// NewAccredsKeycloakClient creates a new mock instance.
func NewAccredsKeycloakClient(ctrl *gomock.Controller) *AccredsKeycloakClient {
	mock := &AccredsKeycloakClient{ctrl: ctrl}
	mock.recorder = &AccredsKeycloakClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *AccredsKeycloakClient) EXPECT() *AccredsKeycloakClientMockRecorder {
	return m.recorder
}

// GetRealm mocks base method.
func (m *AccredsKeycloakClient) GetRealm(accessToken, realmName string) (keycloak.RealmRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRealm", accessToken, realmName)
	ret0, _ := ret[0].(keycloak.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealm indicates an expected call of GetRealm.
func (mr *AccredsKeycloakClientMockRecorder) GetRealm(accessToken, realmName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealm", reflect.TypeOf((*AccredsKeycloakClient)(nil).GetRealm), accessToken, realmName)
}

// GetUser mocks base method.
func (m *AccredsKeycloakClient) GetUser(accessToken, realmName, userID string) (keycloak.UserRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUser", accessToken, realmName, userID)
	ret0, _ := ret[0].(keycloak.UserRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser.
func (mr *AccredsKeycloakClientMockRecorder) GetUser(accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*AccredsKeycloakClient)(nil).GetUser), accessToken, realmName, userID)
}

// UpdateUser mocks base method.
func (m *AccredsKeycloakClient) UpdateUser(accessToken, realmName, userID string, user keycloak.UserRepresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUser", accessToken, realmName, userID, user)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser.
func (mr *AccredsKeycloakClientMockRecorder) UpdateUser(accessToken, realmName, userID, user any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*AccredsKeycloakClient)(nil).UpdateUser), accessToken, realmName, userID, user)
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

// GetGroup mocks base method.
func (m *KeycloakClient) GetGroup(accessToken, realmName, groupID string) (keycloak.GroupRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroup", accessToken, realmName, groupID)
	ret0, _ := ret[0].(keycloak.GroupRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroup indicates an expected call of GetGroup.
func (mr *KeycloakClientMockRecorder) GetGroup(accessToken, realmName, groupID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroup", reflect.TypeOf((*KeycloakClient)(nil).GetGroup), accessToken, realmName, groupID)
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

// KeycloakForTechnicalClient is a mock of KeycloakForTechnicalClient interface.
type KeycloakForTechnicalClient struct {
	ctrl     *gomock.Controller
	recorder *KeycloakForTechnicalClientMockRecorder
	isgomock struct{}
}

// KeycloakForTechnicalClientMockRecorder is the mock recorder for KeycloakForTechnicalClient.
type KeycloakForTechnicalClientMockRecorder struct {
	mock *KeycloakForTechnicalClient
}

// NewKeycloakForTechnicalClient creates a new mock instance.
func NewKeycloakForTechnicalClient(ctrl *gomock.Controller) *KeycloakForTechnicalClient {
	mock := &KeycloakForTechnicalClient{ctrl: ctrl}
	mock.recorder = &KeycloakForTechnicalClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *KeycloakForTechnicalClient) EXPECT() *KeycloakForTechnicalClientMockRecorder {
	return m.recorder
}

// GetRealm mocks base method.
func (m *KeycloakForTechnicalClient) GetRealm(accessToken, realmName string) (keycloak.RealmRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRealm", accessToken, realmName)
	ret0, _ := ret[0].(keycloak.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealm indicates an expected call of GetRealm.
func (mr *KeycloakForTechnicalClientMockRecorder) GetRealm(accessToken, realmName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealm", reflect.TypeOf((*KeycloakForTechnicalClient)(nil).GetRealm), accessToken, realmName)
}

// GetUsers mocks base method.
func (m *KeycloakForTechnicalClient) GetUsers(accessToken, reqRealmName, targetRealmName string, paramKV ...string) (keycloak.UsersPageRepresentation, error) {
	m.ctrl.T.Helper()
	varargs := []any{accessToken, reqRealmName, targetRealmName}
	for _, a := range paramKV {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].(keycloak.UsersPageRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *KeycloakForTechnicalClientMockRecorder) GetUsers(accessToken, reqRealmName, targetRealmName any, paramKV ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{accessToken, reqRealmName, targetRealmName}, paramKV...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*KeycloakForTechnicalClient)(nil).GetUsers), varargs...)
}

// LogoutAllSessions mocks base method.
func (m *KeycloakForTechnicalClient) LogoutAllSessions(accessToken, realmName, userID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LogoutAllSessions", accessToken, realmName, userID)
	ret0, _ := ret[0].(error)
	return ret0
}

// LogoutAllSessions indicates an expected call of LogoutAllSessions.
func (mr *KeycloakForTechnicalClientMockRecorder) LogoutAllSessions(accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LogoutAllSessions", reflect.TypeOf((*KeycloakForTechnicalClient)(nil).LogoutAllSessions), accessToken, realmName, userID)
}

// Logger is a mock of Logger interface.
type Logger struct {
	ctrl     *gomock.Controller
	recorder *LoggerMockRecorder
	isgomock struct{}
}

// LoggerMockRecorder is the mock recorder for Logger.
type LoggerMockRecorder struct {
	mock *Logger
}

// NewLogger creates a new mock instance.
func NewLogger(ctrl *gomock.Controller) *Logger {
	mock := &Logger{ctrl: ctrl}
	mock.recorder = &LoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Logger) EXPECT() *LoggerMockRecorder {
	return m.recorder
}

// Debug mocks base method.
func (m *Logger) Debug(ctx context.Context, keyvals ...any) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range keyvals {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debug", varargs...)
}

// Debug indicates an expected call of Debug.
func (mr *LoggerMockRecorder) Debug(ctx any, keyvals ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, keyvals...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debug", reflect.TypeOf((*Logger)(nil).Debug), varargs...)
}

// Error mocks base method.
func (m *Logger) Error(ctx context.Context, keyvals ...any) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range keyvals {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Error", varargs...)
}

// Error indicates an expected call of Error.
func (mr *LoggerMockRecorder) Error(ctx any, keyvals ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, keyvals...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Error", reflect.TypeOf((*Logger)(nil).Error), varargs...)
}

// Info mocks base method.
func (m *Logger) Info(ctx context.Context, keyvals ...any) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range keyvals {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Info", varargs...)
}

// Info indicates an expected call of Info.
func (mr *LoggerMockRecorder) Info(ctx any, keyvals ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, keyvals...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Info", reflect.TypeOf((*Logger)(nil).Info), varargs...)
}

// Warn mocks base method.
func (m *Logger) Warn(ctx context.Context, keyvals ...any) {
	m.ctrl.T.Helper()
	varargs := []any{ctx}
	for _, a := range keyvals {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Warn", varargs...)
}

// Warn indicates an expected call of Warn.
func (mr *LoggerMockRecorder) Warn(ctx any, keyvals ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{ctx}, keyvals...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Warn", reflect.TypeOf((*Logger)(nil).Warn), varargs...)
}

// HTTPClient is a mock of HTTPClient interface.
type HTTPClient struct {
	ctrl     *gomock.Controller
	recorder *HTTPClientMockRecorder
	isgomock struct{}
}

// HTTPClientMockRecorder is the mock recorder for HTTPClient.
type HTTPClientMockRecorder struct {
	mock *HTTPClient
}

// NewHTTPClient creates a new mock instance.
func NewHTTPClient(ctrl *gomock.Controller) *HTTPClient {
	mock := &HTTPClient{ctrl: ctrl}
	mock.recorder = &HTTPClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *HTTPClient) EXPECT() *HTTPClientMockRecorder {
	return m.recorder
}

// Get mocks base method.
func (m *HTTPClient) Get(data any, plugins ...plugin.Plugin) error {
	m.ctrl.T.Helper()
	varargs := []any{data}
	for _, a := range plugins {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Get", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Get indicates an expected call of Get.
func (mr *HTTPClientMockRecorder) Get(data any, plugins ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{data}, plugins...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*HTTPClient)(nil).Get), varargs...)
}

// OnboardingKeycloakClient is a mock of OnboardingKeycloakClient interface.
type OnboardingKeycloakClient struct {
	ctrl     *gomock.Controller
	recorder *OnboardingKeycloakClientMockRecorder
	isgomock struct{}
}

// OnboardingKeycloakClientMockRecorder is the mock recorder for OnboardingKeycloakClient.
type OnboardingKeycloakClientMockRecorder struct {
	mock *OnboardingKeycloakClient
}

// NewOnboardingKeycloakClient creates a new mock instance.
func NewOnboardingKeycloakClient(ctrl *gomock.Controller) *OnboardingKeycloakClient {
	mock := &OnboardingKeycloakClient{ctrl: ctrl}
	mock.recorder = &OnboardingKeycloakClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *OnboardingKeycloakClient) EXPECT() *OnboardingKeycloakClientMockRecorder {
	return m.recorder
}

// CreateUser mocks base method.
func (m *OnboardingKeycloakClient) CreateUser(accessToken, realmName, targetRealmName string, user keycloak.UserRepresentation, paramKV ...string) (string, error) {
	m.ctrl.T.Helper()
	varargs := []any{accessToken, realmName, targetRealmName, user}
	for _, a := range paramKV {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateUser", varargs...)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *OnboardingKeycloakClientMockRecorder) CreateUser(accessToken, realmName, targetRealmName, user any, paramKV ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{accessToken, realmName, targetRealmName, user}, paramKV...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*OnboardingKeycloakClient)(nil).CreateUser), varargs...)
}

// DeleteUser mocks base method.
func (m *OnboardingKeycloakClient) DeleteUser(accessToken, realmName, userID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteUser", accessToken, realmName, userID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser.
func (mr *OnboardingKeycloakClientMockRecorder) DeleteUser(accessToken, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*OnboardingKeycloakClient)(nil).DeleteUser), accessToken, realmName, userID)
}

// ExecuteActionsEmail mocks base method.
func (m *OnboardingKeycloakClient) ExecuteActionsEmail(accessToken, reqRealmName, targetRealmName, userID string, actions []string, paramKV ...string) error {
	m.ctrl.T.Helper()
	varargs := []any{accessToken, reqRealmName, targetRealmName, userID, actions}
	for _, a := range paramKV {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ExecuteActionsEmail", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExecuteActionsEmail indicates an expected call of ExecuteActionsEmail.
func (mr *OnboardingKeycloakClientMockRecorder) ExecuteActionsEmail(accessToken, reqRealmName, targetRealmName, userID, actions any, paramKV ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{accessToken, reqRealmName, targetRealmName, userID, actions}, paramKV...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecuteActionsEmail", reflect.TypeOf((*OnboardingKeycloakClient)(nil).ExecuteActionsEmail), varargs...)
}

// GenerateTrustIDAuthToken mocks base method.
func (m *OnboardingKeycloakClient) GenerateTrustIDAuthToken(accessToken, reqRealmName, realmName, userID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateTrustIDAuthToken", accessToken, reqRealmName, realmName, userID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GenerateTrustIDAuthToken indicates an expected call of GenerateTrustIDAuthToken.
func (mr *OnboardingKeycloakClientMockRecorder) GenerateTrustIDAuthToken(accessToken, reqRealmName, realmName, userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateTrustIDAuthToken", reflect.TypeOf((*OnboardingKeycloakClient)(nil).GenerateTrustIDAuthToken), accessToken, reqRealmName, realmName, userID)
}

// GetRealm mocks base method.
func (m *OnboardingKeycloakClient) GetRealm(accessToken, realmName string) (keycloak.RealmRepresentation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRealm", accessToken, realmName)
	ret0, _ := ret[0].(keycloak.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealm indicates an expected call of GetRealm.
func (mr *OnboardingKeycloakClientMockRecorder) GetRealm(accessToken, realmName any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealm", reflect.TypeOf((*OnboardingKeycloakClient)(nil).GetRealm), accessToken, realmName)
}

// GetUsers mocks base method.
func (m *OnboardingKeycloakClient) GetUsers(accessToken, reqRealmName, targetRealmName string, paramKV ...string) (keycloak.UsersPageRepresentation, error) {
	m.ctrl.T.Helper()
	varargs := []any{accessToken, reqRealmName, targetRealmName}
	for _, a := range paramKV {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].(keycloak.UsersPageRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *OnboardingKeycloakClientMockRecorder) GetUsers(accessToken, reqRealmName, targetRealmName any, paramKV ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{accessToken, reqRealmName, targetRealmName}, paramKV...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*OnboardingKeycloakClient)(nil).GetUsers), varargs...)
}

// SendEmail mocks base method.
func (m *OnboardingKeycloakClient) SendEmail(accessToken, reqRealmName, realmName string, emailRep keycloak.EmailRepresentation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendEmail", accessToken, reqRealmName, realmName, emailRep)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendEmail indicates an expected call of SendEmail.
func (mr *OnboardingKeycloakClientMockRecorder) SendEmail(accessToken, reqRealmName, realmName, emailRep any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendEmail", reflect.TypeOf((*OnboardingKeycloakClient)(nil).SendEmail), accessToken, reqRealmName, realmName, emailRep)
}

// KeycloakURIProvider is a mock of KeycloakURIProvider interface.
type KeycloakURIProvider struct {
	ctrl     *gomock.Controller
	recorder *KeycloakURIProviderMockRecorder
	isgomock struct{}
}

// KeycloakURIProviderMockRecorder is the mock recorder for KeycloakURIProvider.
type KeycloakURIProviderMockRecorder struct {
	mock *KeycloakURIProvider
}

// NewKeycloakURIProvider creates a new mock instance.
func NewKeycloakURIProvider(ctrl *gomock.Controller) *KeycloakURIProvider {
	mock := &KeycloakURIProvider{ctrl: ctrl}
	mock.recorder = &KeycloakURIProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *KeycloakURIProvider) EXPECT() *KeycloakURIProviderMockRecorder {
	return m.recorder
}

// GetBaseURI mocks base method.
func (m *KeycloakURIProvider) GetBaseURI(realm string) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBaseURI", realm)
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBaseURI indicates an expected call of GetBaseURI.
func (mr *KeycloakURIProviderMockRecorder) GetBaseURI(realm any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBaseURI", reflect.TypeOf((*KeycloakURIProvider)(nil).GetBaseURI), realm)
}
