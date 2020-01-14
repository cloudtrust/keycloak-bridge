package management

import (
	"context"
	"time"

	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
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
func (m *configDBModuleLoggingMW) StoreOrUpdate(ctx context.Context, realmName string, config dto.RealmConfiguration) error {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "StoreOrUpdate", "args", realmName, config, "took", time.Since(begin))
	}(time.Now())
	return m.next.StoreOrUpdate(ctx, realmName, config)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) GetConfiguration(ctx context.Context, realmName string) (dto.RealmConfiguration, error) {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "GetConfiguration", "args", realmName, "took", time.Since(begin))
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) NewTransaction(ctx context.Context) (database.Transaction, error) {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "NewTransaction", "took", time.Since(begin))
	}(time.Now())
	return m.next.NewTransaction(ctx)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) GetAuthorizations(ctx context.Context, realmID string, groupID string) ([]dto.Authorization, error) {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "GetAuthorizations", "args", "["+realmID+","+groupID+"]", "took", time.Since(begin))
	}(time.Now())
	return m.next.GetAuthorizations(ctx, realmID, groupID)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) CreateAuthorization(ctx context.Context, authz dto.Authorization) error {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "CreateAuthorization", "args", authz, "took", time.Since(begin))
	}(time.Now())
	return m.next.CreateAuthorization(ctx, authz)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) DeleteAuthorizations(ctx context.Context, realmID string, groupID string) error {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "DeleteAuthorizations", "args", "["+realmID+","+groupID+"]", "took", time.Since(begin))
	}(time.Now())
	return m.next.DeleteAuthorizations(ctx, realmID, groupID)
}

// configDBModuleLoggingMW implements ConfigurationDBModule.
func (m *configDBModuleLoggingMW) DeleteAuthorizationsWithGroupID(ctx context.Context, groupID string) error {
	defer func(begin time.Time) {
		m.logger.Info(ctx, "method", "DeleteAuthorizationsWithGroupID", "args", groupID, "took", time.Since(begin))
	}(time.Now())
	return m.next.DeleteAuthorizationsWithGroupID(ctx, groupID)
}
