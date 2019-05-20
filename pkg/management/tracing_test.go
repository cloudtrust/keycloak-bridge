package management

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
)

func TestConfigurationDBModuleMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockConfigDBModule = mock.NewConfigurationDBModule(mockCtrl)
	var mockTracer = mock.NewOpentracingClient(mockCtrl)
	var mockFinisher = mock.NewFinisher(mockCtrl)

	var m = MakeConfigurationDBModuleTracingMW(mockTracer)(mockConfigDBModule)
	var corrID = "abc-def-ghi"
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)

	// GetConfiguration / Spawn
	mockConfigDBModule.EXPECT().GetConfiguration(gomock.Any(), "realmID").Return("", nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.GetConfiguration(ctx, "realmID")

	// GetConfiguration / Not spawn
	mockConfigDBModule.EXPECT().GetConfiguration(gomock.Any(), "realmID").Return("", nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Store configuration / Spawn
	mockConfigDBModule.EXPECT().StoreOrUpdate(gomock.Any(), "realmID", "{}").Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", corrID).Return(ctx, mockFinisher).Times(1)
	mockFinisher.EXPECT().Finish().Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")

	// Store configuration / Spawn
	mockConfigDBModule.EXPECT().StoreOrUpdate(gomock.Any(), "realmID", "{}").Return(nil).Times(1)
	mockTracer.EXPECT().TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", corrID).Return(ctx, nil).Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")
}
