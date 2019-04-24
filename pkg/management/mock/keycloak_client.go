// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/pkg/management (interfaces: KeycloakClient)

// Package mock is a generated GoMock package.
package mock

import (
	keycloak_client "github.com/cloudtrust/keycloak-client"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// KeycloakClient is a mock of KeycloakClient interface
type KeycloakClient struct {
	ctrl     *gomock.Controller
	recorder *KeycloakClientMockRecorder
}

// KeycloakClientMockRecorder is the mock recorder for KeycloakClient
type KeycloakClientMockRecorder struct {
	mock *KeycloakClient
}

// NewKeycloakClient creates a new mock instance
func NewKeycloakClient(ctrl *gomock.Controller) *KeycloakClient {
	mock := &KeycloakClient{ctrl: ctrl}
	mock.recorder = &KeycloakClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *KeycloakClient) EXPECT() *KeycloakClientMockRecorder {
	return m.recorder
}

// AddClientRolesToUserRoleMapping mocks base method
func (m *KeycloakClient) AddClientRolesToUserRoleMapping(arg0, arg1, arg2, arg3 string, arg4 []keycloak_client.RoleRepresentation) error {
	ret := m.ctrl.Call(m, "AddClientRolesToUserRoleMapping", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddClientRolesToUserRoleMapping indicates an expected call of AddClientRolesToUserRoleMapping
func (mr *KeycloakClientMockRecorder) AddClientRolesToUserRoleMapping(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddClientRolesToUserRoleMapping", reflect.TypeOf((*KeycloakClient)(nil).AddClientRolesToUserRoleMapping), arg0, arg1, arg2, arg3, arg4)
}

// CreateClientRole mocks base method
func (m *KeycloakClient) CreateClientRole(arg0, arg1, arg2 string, arg3 keycloak_client.RoleRepresentation) (string, error) {
	ret := m.ctrl.Call(m, "CreateClientRole", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateClientRole indicates an expected call of CreateClientRole
func (mr *KeycloakClientMockRecorder) CreateClientRole(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateClientRole", reflect.TypeOf((*KeycloakClient)(nil).CreateClientRole), arg0, arg1, arg2, arg3)
}

// CreateUser mocks base method
func (m *KeycloakClient) CreateUser(arg0, arg1 string, arg2 keycloak_client.UserRepresentation) (string, error) {
	ret := m.ctrl.Call(m, "CreateUser", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser
func (mr *KeycloakClientMockRecorder) CreateUser(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*KeycloakClient)(nil).CreateUser), arg0, arg1, arg2)
}

// DeleteCredentialsForUser mocks base method
func (m *KeycloakClient) DeleteCredentialsForUser(arg0, arg1, arg2, arg3, arg4 string) error {
	ret := m.ctrl.Call(m, "DeleteCredentialsForUser", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteCredentialsForUser indicates an expected call of DeleteCredentialsForUser
func (mr *KeycloakClientMockRecorder) DeleteCredentialsForUser(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteCredentialsForUser", reflect.TypeOf((*KeycloakClient)(nil).DeleteCredentialsForUser), arg0, arg1, arg2, arg3, arg4)
}

// DeleteUser mocks base method
func (m *KeycloakClient) DeleteUser(arg0, arg1, arg2 string) error {
	ret := m.ctrl.Call(m, "DeleteUser", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteUser indicates an expected call of DeleteUser
func (mr *KeycloakClientMockRecorder) DeleteUser(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteUser", reflect.TypeOf((*KeycloakClient)(nil).DeleteUser), arg0, arg1, arg2)
}

// ExecuteActionsEmail mocks base method
func (m *KeycloakClient) ExecuteActionsEmail(arg0, arg1, arg2 string, arg3 []string, arg4 ...string) error {
	varargs := []interface{}{arg0, arg1, arg2, arg3}
	for _, a := range arg4 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ExecuteActionsEmail", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExecuteActionsEmail indicates an expected call of ExecuteActionsEmail
func (mr *KeycloakClientMockRecorder) ExecuteActionsEmail(arg0, arg1, arg2, arg3 interface{}, arg4 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1, arg2, arg3}, arg4...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecuteActionsEmail", reflect.TypeOf((*KeycloakClient)(nil).ExecuteActionsEmail), varargs...)
}

// GetClient mocks base method
func (m *KeycloakClient) GetClient(arg0, arg1, arg2 string) (keycloak_client.ClientRepresentation, error) {
	ret := m.ctrl.Call(m, "GetClient", arg0, arg1, arg2)
	ret0, _ := ret[0].(keycloak_client.ClientRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClient indicates an expected call of GetClient
func (mr *KeycloakClientMockRecorder) GetClient(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClient", reflect.TypeOf((*KeycloakClient)(nil).GetClient), arg0, arg1, arg2)
}

// GetClientRoleMappings mocks base method
func (m *KeycloakClient) GetClientRoleMappings(arg0, arg1, arg2, arg3 string) ([]keycloak_client.RoleRepresentation, error) {
	ret := m.ctrl.Call(m, "GetClientRoleMappings", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]keycloak_client.RoleRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClientRoleMappings indicates an expected call of GetClientRoleMappings
func (mr *KeycloakClientMockRecorder) GetClientRoleMappings(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClientRoleMappings", reflect.TypeOf((*KeycloakClient)(nil).GetClientRoleMappings), arg0, arg1, arg2, arg3)
}

// GetClientRoles mocks base method
func (m *KeycloakClient) GetClientRoles(arg0, arg1, arg2 string) ([]keycloak_client.RoleRepresentation, error) {
	ret := m.ctrl.Call(m, "GetClientRoles", arg0, arg1, arg2)
	ret0, _ := ret[0].([]keycloak_client.RoleRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClientRoles indicates an expected call of GetClientRoles
func (mr *KeycloakClientMockRecorder) GetClientRoles(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClientRoles", reflect.TypeOf((*KeycloakClient)(nil).GetClientRoles), arg0, arg1, arg2)
}

// GetClients mocks base method
func (m *KeycloakClient) GetClients(arg0, arg1 string, arg2 ...string) ([]keycloak_client.ClientRepresentation, error) {
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetClients", varargs...)
	ret0, _ := ret[0].([]keycloak_client.ClientRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetClients indicates an expected call of GetClients
func (mr *KeycloakClientMockRecorder) GetClients(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClients", reflect.TypeOf((*KeycloakClient)(nil).GetClients), varargs...)
}

// GetCredentialsForUser mocks base method
func (m *KeycloakClient) GetCredentialsForUser(arg0, arg1, arg2, arg3 string) ([]keycloak_client.CredentialRepresentation, error) {
	ret := m.ctrl.Call(m, "GetCredentialsForUser", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]keycloak_client.CredentialRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCredentialsForUser indicates an expected call of GetCredentialsForUser
func (mr *KeycloakClientMockRecorder) GetCredentialsForUser(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCredentialsForUser", reflect.TypeOf((*KeycloakClient)(nil).GetCredentialsForUser), arg0, arg1, arg2, arg3)
}

// GetGroup mocks base method
func (m *KeycloakClient) GetGroup(arg0, arg1, arg2 string) (keycloak_client.GroupRepresentation, error) {
	ret := m.ctrl.Call(m, "GetGroup", arg0, arg1, arg2)
	ret0, _ := ret[0].(keycloak_client.GroupRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroup indicates an expected call of GetGroup
func (mr *KeycloakClientMockRecorder) GetGroup(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroup", reflect.TypeOf((*KeycloakClient)(nil).GetGroup), arg0, arg1, arg2)
}

// GetGroupsOfUser mocks base method
func (m *KeycloakClient) GetGroupsOfUser(arg0, arg1, arg2 string) ([]keycloak_client.GroupRepresentation, error) {
	ret := m.ctrl.Call(m, "GetGroupsOfUser", arg0, arg1, arg2)
	ret0, _ := ret[0].([]keycloak_client.GroupRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupsOfUser indicates an expected call of GetGroupsOfUser
func (mr *KeycloakClientMockRecorder) GetGroupsOfUser(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupsOfUser", reflect.TypeOf((*KeycloakClient)(nil).GetGroupsOfUser), arg0, arg1, arg2)
}

// GetRealm mocks base method
func (m *KeycloakClient) GetRealm(arg0, arg1 string) (keycloak_client.RealmRepresentation, error) {
	ret := m.ctrl.Call(m, "GetRealm", arg0, arg1)
	ret0, _ := ret[0].(keycloak_client.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealm indicates an expected call of GetRealm
func (mr *KeycloakClientMockRecorder) GetRealm(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealm", reflect.TypeOf((*KeycloakClient)(nil).GetRealm), arg0, arg1)
}

// GetRealmLevelRoleMappings mocks base method
func (m *KeycloakClient) GetRealmLevelRoleMappings(arg0, arg1, arg2 string) ([]keycloak_client.RoleRepresentation, error) {
	ret := m.ctrl.Call(m, "GetRealmLevelRoleMappings", arg0, arg1, arg2)
	ret0, _ := ret[0].([]keycloak_client.RoleRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealmLevelRoleMappings indicates an expected call of GetRealmLevelRoleMappings
func (mr *KeycloakClientMockRecorder) GetRealmLevelRoleMappings(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealmLevelRoleMappings", reflect.TypeOf((*KeycloakClient)(nil).GetRealmLevelRoleMappings), arg0, arg1, arg2)
}

// GetRealms mocks base method
func (m *KeycloakClient) GetRealms(arg0 string) ([]keycloak_client.RealmRepresentation, error) {
	ret := m.ctrl.Call(m, "GetRealms", arg0)
	ret0, _ := ret[0].([]keycloak_client.RealmRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRealms indicates an expected call of GetRealms
func (mr *KeycloakClientMockRecorder) GetRealms(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRealms", reflect.TypeOf((*KeycloakClient)(nil).GetRealms), arg0)
}

// GetRole mocks base method
func (m *KeycloakClient) GetRole(arg0, arg1, arg2 string) (keycloak_client.RoleRepresentation, error) {
	ret := m.ctrl.Call(m, "GetRole", arg0, arg1, arg2)
	ret0, _ := ret[0].(keycloak_client.RoleRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRole indicates an expected call of GetRole
func (mr *KeycloakClientMockRecorder) GetRole(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRole", reflect.TypeOf((*KeycloakClient)(nil).GetRole), arg0, arg1, arg2)
}

// GetRoles mocks base method
func (m *KeycloakClient) GetRoles(arg0, arg1 string) ([]keycloak_client.RoleRepresentation, error) {
	ret := m.ctrl.Call(m, "GetRoles", arg0, arg1)
	ret0, _ := ret[0].([]keycloak_client.RoleRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRoles indicates an expected call of GetRoles
func (mr *KeycloakClientMockRecorder) GetRoles(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRoles", reflect.TypeOf((*KeycloakClient)(nil).GetRoles), arg0, arg1)
}

// GetUser mocks base method
func (m *KeycloakClient) GetUser(arg0, arg1, arg2 string) (keycloak_client.UserRepresentation, error) {
	ret := m.ctrl.Call(m, "GetUser", arg0, arg1, arg2)
	ret0, _ := ret[0].(keycloak_client.UserRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUser indicates an expected call of GetUser
func (mr *KeycloakClientMockRecorder) GetUser(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUser", reflect.TypeOf((*KeycloakClient)(nil).GetUser), arg0, arg1, arg2)
}

// GetUsers mocks base method
func (m *KeycloakClient) GetUsers(arg0, arg1, arg2 string, arg3 ...string) ([]keycloak_client.UserRepresentation, error) {
	varargs := []interface{}{arg0, arg1, arg2}
	for _, a := range arg3 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].([]keycloak_client.UserRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers
func (mr *KeycloakClientMockRecorder) GetUsers(arg0, arg1, arg2 interface{}, arg3 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1, arg2}, arg3...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*KeycloakClient)(nil).GetUsers), varargs...)
}

// ResetPassword mocks base method
func (m *KeycloakClient) ResetPassword(arg0, arg1, arg2 string, arg3 keycloak_client.CredentialRepresentation) error {
	ret := m.ctrl.Call(m, "ResetPassword", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// ResetPassword indicates an expected call of ResetPassword
func (mr *KeycloakClientMockRecorder) ResetPassword(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ResetPassword", reflect.TypeOf((*KeycloakClient)(nil).ResetPassword), arg0, arg1, arg2, arg3)
}

// SendNewEnrolmentCode mocks base method
func (m *KeycloakClient) SendNewEnrolmentCode(arg0, arg1, arg2 string) error {
	ret := m.ctrl.Call(m, "SendNewEnrolmentCode", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendNewEnrolmentCode indicates an expected call of SendNewEnrolmentCode
func (mr *KeycloakClientMockRecorder) SendNewEnrolmentCode(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendNewEnrolmentCode", reflect.TypeOf((*KeycloakClient)(nil).SendNewEnrolmentCode), arg0, arg1, arg2)
}

// SendVerifyEmail mocks base method
func (m *KeycloakClient) SendVerifyEmail(arg0, arg1, arg2 string, arg3 ...string) error {
	varargs := []interface{}{arg0, arg1, arg2}
	for _, a := range arg3 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SendVerifyEmail", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendVerifyEmail indicates an expected call of SendVerifyEmail
func (mr *KeycloakClientMockRecorder) SendVerifyEmail(arg0, arg1, arg2 interface{}, arg3 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1, arg2}, arg3...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendVerifyEmail", reflect.TypeOf((*KeycloakClient)(nil).SendVerifyEmail), varargs...)
}

// UpdateUser mocks base method
func (m *KeycloakClient) UpdateUser(arg0, arg1, arg2 string, arg3 keycloak_client.UserRepresentation) error {
	ret := m.ctrl.Call(m, "UpdateUser", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateUser indicates an expected call of UpdateUser
func (mr *KeycloakClientMockRecorder) UpdateUser(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUser", reflect.TypeOf((*KeycloakClient)(nil).UpdateUser), arg0, arg1, arg2, arg3)
}
