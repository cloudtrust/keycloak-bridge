package management

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
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
func (m *configDBModuleLoggingMW) StoreOrUpdate(ctx context.Context, realmName string, configJSON string) error {
	defer func(begin time.Time) {
		m.logger.Log("method", "StoreOrUpdate", "args", realmName, configJSON, "took", time.Since(begin))
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, configJSON)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) GetConfiguration(ctx context.Context, realmName string) (string, error) {
	defer func(begin time.Time) {
		m.logger.Log("method", "GetConfiguration", "args", realmName, "took", time.Since(begin))
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}
