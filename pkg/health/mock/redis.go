// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/pkg/health (interfaces: RedisModule,Redis)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	health "github.com/cloudtrust/keycloak-bridge/pkg/health"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// RedisModule is a mock of RedisModule interface
type RedisModule struct {
	ctrl     *gomock.Controller
	recorder *RedisModuleMockRecorder
}

// RedisModuleMockRecorder is the mock recorder for RedisModule
type RedisModuleMockRecorder struct {
	mock *RedisModule
}

// NewRedisModule creates a new mock instance
func NewRedisModule(ctrl *gomock.Controller) *RedisModule {
	mock := &RedisModule{ctrl: ctrl}
	mock.recorder = &RedisModuleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *RedisModule) EXPECT() *RedisModuleMockRecorder {
	return m.recorder
}

// HealthChecks mocks base method
func (m *RedisModule) HealthChecks(arg0 context.Context) []health.RedisReport {
	ret := m.ctrl.Call(m, "HealthChecks", arg0)
	ret0, _ := ret[0].([]health.RedisReport)
	return ret0
}

// HealthChecks indicates an expected call of HealthChecks
func (mr *RedisModuleMockRecorder) HealthChecks(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HealthChecks", reflect.TypeOf((*RedisModule)(nil).HealthChecks), arg0)
}

// Redis is a mock of Redis interface
type Redis struct {
	ctrl     *gomock.Controller
	recorder *RedisMockRecorder
}

// RedisMockRecorder is the mock recorder for Redis
type RedisMockRecorder struct {
	mock *Redis
}

// NewRedis creates a new mock instance
func NewRedis(ctrl *gomock.Controller) *Redis {
	mock := &Redis{ctrl: ctrl}
	mock.recorder = &RedisMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *Redis) EXPECT() *RedisMockRecorder {
	return m.recorder
}

// Do mocks base method
func (m *Redis) Do(arg0 string, arg1 ...interface{}) (interface{}, error) {
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Do", varargs...)
	ret0, _ := ret[0].(interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Do indicates an expected call of Do
func (mr *RedisMockRecorder) Do(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Do", reflect.TypeOf((*Redis)(nil).Do), varargs...)
}
