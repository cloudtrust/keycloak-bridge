package management

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/tracing"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

// Tracing middleware at module level.
type configDBModuleTracingMW struct {
	tracer tracing.OpentracingClient
	next   ConfigurationDBModule
}

// MakeConfigurationDBModuleTracingMW makes a tracing middleware at component level.
func MakeConfigurationDBModuleTracingMW(tracer tracing.OpentracingClient) func(ConfigurationDBModule) ConfigurationDBModule {
	return func(next ConfigurationDBModule) ConfigurationDBModule {
		return &configDBModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) StoreOrUpdate(ctx context.Context, realmName string, config dto.RealmConfiguration) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.StoreOrUpdate(ctx, realmName, config)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) GetConfiguration(ctx context.Context, realmName string) (dto.RealmConfiguration, error) {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.GetConfiguration(ctx, realmName)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) NewTransaction(ctx context.Context) (database.Transaction, error) {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.NewTransaction(ctx)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) GetAuthorizations(ctx context.Context, realmID string, groupID string) ([]dto.Authorization, error) {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.GetAuthorizations(ctx, realmID, groupID)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) CreateAuthorization(ctx context.Context, authz dto.Authorization) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.CreateAuthorization(ctx, authz)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) DeleteAuthorizations(ctx context.Context, realmID string, groupID string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "configurationDB_module", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.DeleteAuthorizations(ctx, realmID, groupID)
}
