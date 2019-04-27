// Code generated by MockGen. DO NOT EDIT.
// Source: instrumenting.go

// Package mock is a generated GoMock package.
package mock

import (
	influx "github.com/go-kit/kit/metrics/influx"
	gomock "github.com/golang/mock/gomock"
	v2 "github.com/influxdata/influxdb/client/v2"
	reflect "reflect"
	time "time"
)

// Influx is a mock of Influx interface
type Influx struct {
	ctrl     *gomock.Controller
	recorder *InfluxMockRecorder
}

// InfluxMockRecorder is the mock recorder for Influx
type InfluxMockRecorder struct {
	mock *Influx
}

// NewInflux creates a new mock instance
func NewInflux(ctrl *gomock.Controller) *Influx {
	mock := &Influx{ctrl: ctrl}
	mock.recorder = &InfluxMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *Influx) EXPECT() *InfluxMockRecorder {
	return m.recorder
}

// Ping mocks base method
func (m *Influx) Ping(timeout time.Duration) (time.Duration, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ping", timeout)
	ret0, _ := ret[0].(time.Duration)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Ping indicates an expected call of Ping
func (mr *InfluxMockRecorder) Ping(timeout interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ping", reflect.TypeOf((*Influx)(nil).Ping), timeout)
}

// Write mocks base method
func (m *Influx) Write(bp v2.BatchPoints) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Write", bp)
	ret0, _ := ret[0].(error)
	return ret0
}

// Write indicates an expected call of Write
func (mr *InfluxMockRecorder) Write(bp interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*Influx)(nil).Write), bp)
}

// Close mocks base method
func (m *Influx) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (mr *InfluxMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*Influx)(nil).Close))
}

// GoKitMetrics is a mock of GoKitMetrics interface
type GoKitMetrics struct {
	ctrl     *gomock.Controller
	recorder *GoKitMetricsMockRecorder
}

// GoKitMetricsMockRecorder is the mock recorder for GoKitMetrics
type GoKitMetricsMockRecorder struct {
	mock *GoKitMetrics
}

// NewGoKitMetrics creates a new mock instance
func NewGoKitMetrics(ctrl *gomock.Controller) *GoKitMetrics {
	mock := &GoKitMetrics{ctrl: ctrl}
	mock.recorder = &GoKitMetricsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *GoKitMetrics) EXPECT() *GoKitMetricsMockRecorder {
	return m.recorder
}

// NewCounter mocks base method
func (m *GoKitMetrics) NewCounter(name string) *influx.Counter {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewCounter", name)
	ret0, _ := ret[0].(*influx.Counter)
	return ret0
}

// NewCounter indicates an expected call of NewCounter
func (mr *GoKitMetricsMockRecorder) NewCounter(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewCounter", reflect.TypeOf((*GoKitMetrics)(nil).NewCounter), name)
}

// NewGauge mocks base method
func (m *GoKitMetrics) NewGauge(name string) *influx.Gauge {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewGauge", name)
	ret0, _ := ret[0].(*influx.Gauge)
	return ret0
}

// NewGauge indicates an expected call of NewGauge
func (mr *GoKitMetricsMockRecorder) NewGauge(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewGauge", reflect.TypeOf((*GoKitMetrics)(nil).NewGauge), name)
}

// NewHistogram mocks base method
func (m *GoKitMetrics) NewHistogram(name string) *influx.Histogram {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewHistogram", name)
	ret0, _ := ret[0].(*influx.Histogram)
	return ret0
}

// NewHistogram indicates an expected call of NewHistogram
func (mr *GoKitMetricsMockRecorder) NewHistogram(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewHistogram", reflect.TypeOf((*GoKitMetrics)(nil).NewHistogram), name)
}

// WriteLoop mocks base method
func (m *GoKitMetrics) WriteLoop(c <-chan time.Time, w influx.BatchPointsWriter) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "WriteLoop", c, w)
}

// WriteLoop indicates an expected call of WriteLoop
func (mr *GoKitMetricsMockRecorder) WriteLoop(c, w interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteLoop", reflect.TypeOf((*GoKitMetrics)(nil).WriteLoop), c, w)
}
