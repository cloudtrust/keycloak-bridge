package user

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/mock"
	"github.com/golang/mock/gomock"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
)

func TestComponentTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeComponentTracingMW(mockTracer)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var req = fbUsersRequest("realm")
	var reply = fbUsersResponse([]string{"john", "jane", "doe"})

	// GetUsers.
	mockComponent.EXPECT().GetUsers(gomock.Any(), req).Return(reply, nil).Times(1)
	mockTracer.EXPECT().StartSpan("user_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetUsers(ctx, req)

	// GetUsers error.
	mockComponent.EXPECT().GetUsers(gomock.Any(), req).Return(nil, fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("user_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetUsers(ctx, req)

	// GetUsers without tracer.
	mockComponent.EXPECT().GetUsers(gomock.Any(), req).Return(reply, nil).Times(1)
	m.GetUsers(context.Background(), req)

	// GetUsers without correlation ID.
	mockTracer.EXPECT().StartSpan("user_component", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.GetUsers(opentracing.ContextWithSpan(context.Background(), mockSpan), req)
	}
	assert.Panics(t, f)
}

func TestModuleTracingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)
	var mockModule = mock.NewModule(mockCtrl)

	var m = MakeModuleTracingMW(mockTracer)(mockModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)
	var names = []string{"john", "jane", "doe"}

	// GetUsers.
	mockModule.EXPECT().GetUsers(gomock.Any(), "realm").Return(names, nil).Times(1)
	mockTracer.EXPECT().StartSpan("user_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetUsers(ctx, "realm")

	// GetUsers error.
	mockModule.EXPECT().GetUsers(gomock.Any(), "realm").Return(nil, fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("user_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetUsers(ctx, "realm")

	// GetUsers without tracer.
	mockModule.EXPECT().GetUsers(gomock.Any(), "realm").Return(names, nil).Times(1)
	m.GetUsers(context.Background(), "realm")

	// GetUsers without correlation ID.
	mockTracer.EXPECT().StartSpan("user_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.GetUsers(opentracing.ContextWithSpan(context.Background(), mockSpan), "realm")
	}
	assert.Panics(t, f)
}
