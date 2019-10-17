package keycloakb

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	cm "github.com/cloudtrust/common-service/metrics"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

// Instrumenting middleware at module level.
type configDBModuleInstrumentingMW struct {
	h    cm.Histogram
	next ConfigurationDBModule
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	StoreOrUpdate(context.Context, string, dto.RealmConfiguration) error
	GetConfiguration(context.Context, string) (dto.RealmConfiguration, error)
}

// MakeConfigurationDBModuleInstrumentingMW makes an instrumenting middleware at module level.
func MakeConfigurationDBModuleInstrumentingMW(h cm.Histogram) func(ConfigurationDBModule) ConfigurationDBModule {
	return func(next ConfigurationDBModule) ConfigurationDBModule {
		return &configDBModuleInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) StoreOrUpdate(ctx context.Context, realmName string, config dto.RealmConfiguration) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, config)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetConfiguration(ctx context.Context, realmName string) (dto.RealmConfiguration, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}
