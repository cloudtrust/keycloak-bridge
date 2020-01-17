package keycloakb

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
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
	NewTransaction(context context.Context) (database.Transaction, error)
	StoreOrUpdate(context.Context, string, dto.RealmConfiguration) error
	GetConfiguration(context.Context, string) (dto.RealmConfiguration, error)
	GetAuthorizations(context context.Context, realmID string, groupName string) ([]dto.Authorization, error)
	CreateAuthorization(context context.Context, authz dto.Authorization) error
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
func (m *configDBModuleInstrumentingMW) NewTransaction(ctx context.Context) (database.Transaction, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.NewTransaction(ctx)
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

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) GetAuthorizations(ctx context.Context, realmID string, groupID string) ([]dto.Authorization, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetAuthorizations(ctx, realmID, groupID)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) CreateAuthorization(ctx context.Context, auth dto.Authorization) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.CreateAuthorization(ctx, auth)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) DeleteAuthorizations(ctx context.Context, realmID string, groupID string) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.DeleteAuthorizations(ctx, realmID, groupID)
}

// configDBModuleInstrumentingMW implements Module.
func (m *configDBModuleInstrumentingMW) DeleteAllAuthorizationsWithGroup(ctx context.Context, realmID, groupName string) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.DeleteAllAuthorizationsWithGroup(ctx, realmID, groupName)
}
