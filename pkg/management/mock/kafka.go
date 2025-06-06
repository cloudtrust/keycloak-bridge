// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/cloudtrust/kafka-client (interfaces: Producer)
//
// Generated by this command:
//
//	mockgen --build_flags=--mod=mod -destination=./mock/kafka.go -package=mock -mock_names=Producer=Producer github.com/cloudtrust/kafka-client Producer
//

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// Producer is a mock of Producer interface.
type Producer struct {
	ctrl     *gomock.Controller
	recorder *ProducerMockRecorder
	isgomock struct{}
}

// ProducerMockRecorder is the mock recorder for Producer.
type ProducerMockRecorder struct {
	mock *Producer
}

// NewProducer creates a new mock instance.
func NewProducer(ctrl *gomock.Controller) *Producer {
	mock := &Producer{ctrl: ctrl}
	mock.recorder = &ProducerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Producer) EXPECT() *ProducerMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *Producer) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *ProducerMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*Producer)(nil).Close))
}

// SendMessageBytes mocks base method.
func (m *Producer) SendMessageBytes(content []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMessageBytes", content)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMessageBytes indicates an expected call of SendMessageBytes.
func (mr *ProducerMockRecorder) SendMessageBytes(content any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMessageBytes", reflect.TypeOf((*Producer)(nil).SendMessageBytes), content)
}

// SendPartitionedMessageBytes mocks base method.
func (m *Producer) SendPartitionedMessageBytes(partitionKey string, content []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendPartitionedMessageBytes", partitionKey, content)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendPartitionedMessageBytes indicates an expected call of SendPartitionedMessageBytes.
func (mr *ProducerMockRecorder) SendPartitionedMessageBytes(partitionKey, content any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendPartitionedMessageBytes", reflect.TypeOf((*Producer)(nil).SendPartitionedMessageBytes), partitionKey, content)
}
