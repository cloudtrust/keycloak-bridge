package keycloakb

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/database/sqltypes"
	cm "github.com/cloudtrust/common-service/metrics"
	"github.com/cloudtrust/keycloak-bridge/internal/dto"
)

const (
	// KeyCorrelationID is histogram field for correlation ID
	KeyCorrelationID = "correlation_id"
)

// Instrumenting middleware at module level.
type configDBModuleInstrumentingMW struct {
	h    cm.Histogram
	next ConfigurationDBModule
}

// ConfigurationDBModule is the interface of the configuration module.
type ConfigurationDBModule interface {
	NewTransaction(context context.Context) (sqltypes.Transaction, error)
	GetConfigurations(context.Context, string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error)
	StoreOrUpdateConfiguration(context.Context, string, configuration.RealmConfiguration) error
	GetConfiguration(context.Context, string) (configuration.RealmConfiguration, error)
	StoreOrUpdateAdminConfiguration(context.Context, string, configuration.RealmAdminConfiguration) error
	GetAdminConfiguration(context.Context, string) (configuration.RealmAdminConfiguration, error)
	GetBackOfficeConfiguration(context.Context, string, []string) (dto.BackOfficeConfiguration, error)
	DeleteBackOfficeConfiguration(context.Context, string, string, string, *string, *string) error
	InsertBackOfficeConfiguration(context.Context, string, string, string, string, []string) error
	GetAuthorizations(context context.Context, realmID string, groupName string) ([]configuration.Authorization, error)
	CreateAuthorization(context context.Context, authz configuration.Authorization) error
	DeleteAuthorizations(context context.Context, realmID string, groupName string) error
	DeleteAllAuthorizationsWithGroup(context context.Context, realmName, groupName string) error
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
func (m *configDBModuleInstrumentingMW) NewTransaction(ctx context.Context) (sqltypes.Transaction, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.NewTransaction(ctx)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetConfigurations(ctx context.Context, realmName string) (configuration.RealmConfiguration, configuration.RealmAdminConfiguration, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetConfigurations(ctx, realmName)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) StoreOrUpdateConfiguration(ctx context.Context, realmName string, config configuration.RealmConfiguration) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.StoreOrUpdateConfiguration(ctx, realmName, config)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetConfiguration(ctx context.Context, realmName string) (configuration.RealmConfiguration, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetConfiguration(ctx, realmName)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) StoreOrUpdateAdminConfiguration(ctx context.Context, realmName string, config configuration.RealmAdminConfiguration) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.StoreOrUpdateAdminConfiguration(ctx, realmName, config)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetAdminConfiguration(ctx context.Context, realmName string) (configuration.RealmAdminConfiguration, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetAdminConfiguration(ctx, realmName)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetBackOfficeConfiguration(ctx context.Context, realmName string, groupNames []string) (dto.BackOfficeConfiguration, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetBackOfficeConfiguration(ctx, realmName, groupNames)
}

func (m *configDBModuleInstrumentingMW) DeleteBackOfficeConfiguration(ctx context.Context, realmID string, groupName string, confType string, targetRealmID *string, targetGroupName *string) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, targetGroupName)
}

func (m *configDBModuleInstrumentingMW) InsertBackOfficeConfiguration(ctx context.Context, realmID, groupName, confType, targetRealmID string, targetGroupNames []string) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, targetRealmID, targetGroupNames)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetAuthorizations(ctx context.Context, realmID string, groupID string) ([]configuration.Authorization, error) {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetAuthorizations(ctx, realmID, groupID)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) CreateAuthorization(ctx context.Context, auth configuration.Authorization) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.CreateAuthorization(ctx, auth)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) DeleteAuthorizations(ctx context.Context, realmID string, groupID string) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.DeleteAuthorizations(ctx, realmID, groupID)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) DeleteAllAuthorizationsWithGroup(ctx context.Context, realmID, groupName string) error {
	defer func(begin time.Time) {
		m.h.With(KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
}
