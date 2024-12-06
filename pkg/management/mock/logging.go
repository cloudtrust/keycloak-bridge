// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/common-service/v2/log (interfaces: Logger)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/cloudtrust/common-service/v2/log Logger
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	log "github.com/go-kit/log"
	gomock "go.uber.org/mock/gomock"
)

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

// ToGoKitLogger mocks base method.
func (m *Logger) ToGoKitLogger() log.Logger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ToGoKitLogger")
	ret0, _ := ret[0].(log.Logger)
	return ret0
}

// ToGoKitLogger indicates an expected call of ToGoKitLogger.
func (mr *LoggerMockRecorder) ToGoKitLogger() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ToGoKitLogger", reflect.TypeOf((*Logger)(nil).ToGoKitLogger))
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