// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/common-service/v2/middleware (interfaces: EndpointAvailabilityChecker)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/middleware.go -package=mock -mock_names=EndpointAvailabilityChecker=EndpointAvailabilityChecker github.com/cloudtrust/common-service/v2/middleware EndpointAvailabilityChecker
//

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	reflect "reflect"

	log "github.com/cloudtrust/common-service/v2/log"
	gomock "go.uber.org/mock/gomock"
)

// EndpointAvailabilityChecker is a mock of EndpointAvailabilityChecker interface.
type EndpointAvailabilityChecker struct {
	ctrl     *gomock.Controller
	recorder *EndpointAvailabilityCheckerMockRecorder
	isgomock struct{}
}

// EndpointAvailabilityCheckerMockRecorder is the mock recorder for EndpointAvailabilityChecker.
type EndpointAvailabilityCheckerMockRecorder struct {
	mock *EndpointAvailabilityChecker
}

// NewEndpointAvailabilityChecker creates a new mock instance.
func NewEndpointAvailabilityChecker(ctrl *gomock.Controller) *EndpointAvailabilityChecker {
	mock := &EndpointAvailabilityChecker{ctrl: ctrl}
	mock.recorder = &EndpointAvailabilityCheckerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *EndpointAvailabilityChecker) EXPECT() *EndpointAvailabilityCheckerMockRecorder {
	return m.recorder
}

// CheckAvailability mocks base method.
func (m *EndpointAvailabilityChecker) CheckAvailability(ctx context.Context, logger log.Logger) (context.Context, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckAvailability", ctx, logger)
	ret0, _ := ret[0].(context.Context)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CheckAvailability indicates an expected call of CheckAvailability.
func (mr *EndpointAvailabilityCheckerMockRecorder) CheckAvailability(ctx, logger any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckAvailability", reflect.TypeOf((*EndpointAvailabilityChecker)(nil).CheckAvailability), ctx, logger)
}

// CheckAvailabilityForRealm mocks base method.
func (m *EndpointAvailabilityChecker) CheckAvailabilityForRealm(ctx context.Context, targetRealm string, logger log.Logger) (context.Context, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckAvailabilityForRealm", ctx, targetRealm, logger)
	ret0, _ := ret[0].(context.Context)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CheckAvailabilityForRealm indicates an expected call of CheckAvailabilityForRealm.
func (mr *EndpointAvailabilityCheckerMockRecorder) CheckAvailabilityForRealm(ctx, targetRealm, logger any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckAvailabilityForRealm", reflect.TypeOf((*EndpointAvailabilityChecker)(nil).CheckAvailabilityForRealm), ctx, targetRealm, logger)
}