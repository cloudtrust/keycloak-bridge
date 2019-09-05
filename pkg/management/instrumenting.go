package management

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	cm "github.com/cloudtrust/common-service/metrics"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Instrumenting middleware at module level.
type configDBModuleInstrumentingMW struct {
	h    cm.Histogram
	next internal.ConfigurationDBModule
}

// MakeConfigurationDBModuleInstrumentingMW makes an instrumenting middleware at module level.
func MakeConfigurationDBModuleInstrumentingMW(h cm.Histogram) func(internal.ConfigurationDBModule) internal.ConfigurationDBModule {
	return func(next internal.ConfigurationDBModule) internal.ConfigurationDBModule {
		return &configDBModuleInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) StoreOrUpdate(ctx context.Context, realmName string, configJSON string) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, configJSON)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetConfiguration(ctx context.Context, realmName string) (string, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}
