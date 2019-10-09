package management

import (
	"context"
	"time"

	"github.com/cloudtrust/common-service/log"
	internal "github.com/cloudtrust/keycloak-bridge/internal/keycloakb"
)

// Logging middleware for the statistic module.
type configDBModuleLoggingMW struct {
	logger log.Logger
	next   ConfigurationDBModule
}

// MakeConfigurationDBModuleLoggingMW makes a logging middleware for the statistic module.
func MakeConfigurationDBModuleLoggingMW(log log.Logger) func(ConfigurationDBModule) ConfigurationDBModule {
	return func(next ConfigurationDBModule) ConfigurationDBModule {
		return &configDBModuleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) StoreOrUpdate(ctx context.Context, realmName string, config internal.RealmConfiguration) error {
	defer func(begin time.Time) {
		m.logger.Info("method", "StoreOrUpdate", "args", realmName, config, "took", time.Since(begin))
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, config)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) GetConfiguration(ctx context.Context, realmName string) (internal.RealmConfiguration, error) {
	defer func(begin time.Time) {
		m.logger.Info("method", "GetConfiguration", "args", realmName, "took", time.Since(begin))
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}
