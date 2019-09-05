package management

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/tracing"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Tracing middleware at module level.
type configDBModuleTracingMW struct {
	tracer tracing.OpentracingClient
	next   internal.ConfigurationDBModule
}

// MakeConfigurationDBModuleTracingMW makes a tracing middleware at component level.
func MakeConfigurationDBModuleTracingMW(tracer tracing.OpentracingClient) func(internal.ConfigurationDBModule) internal.ConfigurationDBModule {
	return func(next internal.ConfigurationDBModule) internal.ConfigurationDBModule {
		return &configDBModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) StoreOrUpdate(ctx context.Context, realmName string, configJSON string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.StoreOrUpdate(ctx, realmName, configJSON)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) GetConfiguration(ctx context.Context, realmName string) (string, error) {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.GetConfiguration(ctx, realmName)
}
