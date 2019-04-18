package management

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/assert"
)

func TestConfigurationDBModuleMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConfigDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockTracer = mock.NewTracer(mockCtrl)
	var mockSpan = mock.NewSpan(mockCtrl)
	var mockSpanContext = mock.NewSpanContext(mockCtrl)

	var m = MakeConfigurationDBModuleTracingMW(mockTracer)(mockConfigDBModule)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	ctx = opentracing.ContextWithSpan(ctx, mockSpan)

	// Get configuration.
	mockConfigDBModule.EXPECT().GetConfiguration(gomock.Any(), "realmID").Return("", nil).Times(1)
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Get configuration error
	mockConfigDBModule.EXPECT().GetConfiguration(gomock.Any(), "realmID").Return("", fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Get configuration without tracer.
	mockConfigDBModule.EXPECT().GetConfiguration(gomock.Any(), "realmID").Return("", nil).Times(1)
	m.GetConfiguration(context.Background(), "realmID")

	// Get configuration without correlation ID.
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	var f = func() {
		m.GetConfiguration(opentracing.ContextWithSpan(context.Background(), mockSpan), "realmID")
	}
	assert.Panics(t, f)

	// Store configuration.
	mockConfigDBModule.EXPECT().StoreOrUpdate(gomock.Any(), "realmID", "{}").Return(nil).Times(1)
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")

	// Store configuration error
	mockConfigDBModule.EXPECT().StoreOrUpdate(gomock.Any(), "realmID", "{}").Return(fmt.Errorf("fail")).Times(1)
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	mockSpan.EXPECT().SetTag("correlation_id", corrID).Return(mockSpan).Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")

	// Get configuration without tracer.
	mockConfigDBModule.EXPECT().StoreOrUpdate(gomock.Any(), "realmID", "{}").Return(nil).Times(1)
	m.StoreOrUpdate(context.Background(), "realmID", "{}")

	// Get configuration without correlation ID.
	mockTracer.EXPECT().StartSpan("configurationDB_module", gomock.Any()).Return(mockSpan).Times(1)
	mockSpan.EXPECT().Context().Return(mockSpanContext).Times(1)
	mockSpan.EXPECT().Finish().Return().Times(1)
	f = func() {
		m.StoreOrUpdate(opentracing.ContextWithSpan(context.Background(), mockSpan), "realmID", "{}")
	}
	assert.Panics(t, f)
}
