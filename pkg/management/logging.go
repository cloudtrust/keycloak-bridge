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
	next   internal.ConfigurationDBModule
}

// MakeConfigurationDBModuleLoggingMW makes a logging middleware for the statistic module.
func MakeConfigurationDBModuleLoggingMW(log log.Logger) func(internal.ConfigurationDBModule) internal.ConfigurationDBModule {
	return func(next internal.ConfigurationDBModule) internal.ConfigurationDBModule {
		return &configDBModuleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) StoreOrUpdate(ctx context.Context, realmName string, configJSON string) error {
	defer func(begin time.Time) {
		m.logger.Info("method", "StoreOrUpdate", "args", realmName, configJSON, "took", time.Since(begin))
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, configJSON)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) GetConfiguration(ctx context.Context, realmName string) (string, error) {
	defer func(begin time.Time) {
		m.logger.Info("method", "GetConfiguration", "args", realmName, "took", time.Since(begin))
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}
