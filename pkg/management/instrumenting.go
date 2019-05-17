package management

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/metrics"
)

// Instrumenting middleware at module level.
type configDBModuleInstrumentingMW struct {
	h    metrics.Histogram
	next ConfigurationDBModule
}

// MakeConfigurationDBModuleInstrumentingMW makes an instrumenting middleware at module level.
func MakeConfigurationDBModuleInstrumentingMW(h metrics.Histogram) func(ConfigurationDBModule) ConfigurationDBModule {
	return func(next ConfigurationDBModule) ConfigurationDBModule {
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
