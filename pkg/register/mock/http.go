// Code generated by MockGen. DO NOT EDIT.
// Source: net/http (interfaces: Handler,ResponseWriter)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/http.go -package=mock -mock_names=Handler=Handler,ResponseWriter=ResponseWriter net/http Handler,ResponseWriter
//

// Package mock is a generated GoMock package.
package mock

import (
	http "net/http"
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// Handler is a mock of Handler interface.
type Handler struct {
	ctrl     *gomock.Controller
	recorder *HandlerMockRecorder
	isgomock struct{}
}

// HandlerMockRecorder is the mock recorder for Handler.
type HandlerMockRecorder struct {
	mock *Handler
}

// NewHandler creates a new mock instance.
func NewHandler(ctrl *gomock.Controller) *Handler {
	mock := &Handler{ctrl: ctrl}
	mock.recorder = &HandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Handler) EXPECT() *HandlerMockRecorder {
	return m.recorder
}

// ServeHTTP mocks base method.
func (m *Handler) ServeHTTP(arg0 http.ResponseWriter, arg1 *http.Request) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ServeHTTP", arg0, arg1)
}

// ServeHTTP indicates an expected call of ServeHTTP.
func (mr *HandlerMockRecorder) ServeHTTP(arg0, arg1 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ServeHTTP", reflect.TypeOf((*Handler)(nil).ServeHTTP), arg0, arg1)
}

// ResponseWriter is a mock of ResponseWriter interface.
type ResponseWriter struct {
	ctrl     *gomock.Controller
	recorder *ResponseWriterMockRecorder
	isgomock struct{}
}

// ResponseWriterMockRecorder is the mock recorder for ResponseWriter.
type ResponseWriterMockRecorder struct {
	mock *ResponseWriter
}

// NewResponseWriter creates a new mock instance.
func NewResponseWriter(ctrl *gomock.Controller) *ResponseWriter {
	mock := &ResponseWriter{ctrl: ctrl}
	mock.recorder = &ResponseWriterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *ResponseWriter) EXPECT() *ResponseWriterMockRecorder {
	return m.recorder
}

// Header mocks base method.
func (m *ResponseWriter) Header() http.Header {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header")
	ret0, _ := ret[0].(http.Header)
	return ret0
}

// Header indicates an expected call of Header.
func (mr *ResponseWriterMockRecorder) Header() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*ResponseWriter)(nil).Header))
}

// Write mocks base method.
func (m *ResponseWriter) Write(arg0 []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Write indicates an expected call of Write.
func (mr *ResponseWriterMockRecorder) Write(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*ResponseWriter)(nil).Write), arg0)
}

// WriteHeader mocks base method.
func (m *ResponseWriter) WriteHeader(statusCode int) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "WriteHeader", statusCode)
}

// WriteHeader indicates an expected call of WriteHeader.
func (mr *ResponseWriterMockRecorder) WriteHeader(statusCode any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteHeader", reflect.TypeOf((*ResponseWriter)(nil).WriteHeader), statusCode)
}
