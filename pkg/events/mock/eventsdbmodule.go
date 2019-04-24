// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/keycloak-bridge/pkg/events (interfaces: EventsDBModule)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	events "github.com/cloudtrust/keycloak-bridge/api/events"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// EventsDBModule is a mock of EventsDBModule interface
type EventsDBModule struct {
	ctrl     *gomock.Controller
	recorder *EventsDBModuleMockRecorder
}

// EventsDBModuleMockRecorder is the mock recorder for EventsDBModule
type EventsDBModuleMockRecorder struct {
	mock *EventsDBModule
}

// NewEventsDBModule creates a new mock instance
func NewEventsDBModule(ctrl *gomock.Controller) *EventsDBModule {
	mock := &EventsDBModule{ctrl: ctrl}
	mock.recorder = &EventsDBModuleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *EventsDBModule) EXPECT() *EventsDBModuleMockRecorder {
	return m.recorder
}

// GetEvents mocks base method
func (m *EventsDBModule) GetEvents(arg0 context.Context, arg1 map[string]string) ([]events.AuditRepresentation, error) {
	ret := m.ctrl.Call(m, "GetEvents", arg0, arg1)
	ret0, _ := ret[0].([]events.AuditRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEvents indicates an expected call of GetEvents
func (mr *EventsDBModuleMockRecorder) GetEvents(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEvents", reflect.TypeOf((*EventsDBModule)(nil).GetEvents), arg0, arg1)
}

// GetEventsSummary mocks base method
func (m *EventsDBModule) GetEventsSummary(arg0 context.Context) (events.EventSummaryRepresentation, error) {
	ret := m.ctrl.Call(m, "GetEventsSummary", arg0)
	ret0, _ := ret[0].(events.EventSummaryRepresentation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEventsSummary indicates an expected call of GetEventsSummary
func (mr *EventsDBModuleMockRecorder) GetEventsSummary(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEventsSummary", reflect.TypeOf((*EventsDBModule)(nil).GetEventsSummary), arg0)
}
