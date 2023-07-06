package keycloakb

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakb/mock"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestComponentInstrumentingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewConfigurationDBModule(mockCtrl)
	var mockHistogram = mock.NewHistogram(mockCtrl)

	var m = MakeConfigurationDBModuleInstrumentingMW(mockHistogram)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)
	var realmID = "realmID"
	var groupNames = []string{"group1", "group2", "group3"}
	var groupName = groupNames[0]
	var confType = "customers"
	var action = "TestAction"
	var adminConfig = configuration.RealmAdminConfiguration{}

	t.Run("Get configurations", func(t *testing.T) {
		mockComponent.EXPECT().GetConfigurations(ctx, realmID).Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return()
		_, _, _ = m.GetConfigurations(ctx, realmID)
	})
	t.Run("Get configurations without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetConfigurations(context.Background(), "realmID").Return(configuration.RealmConfiguration{}, configuration.RealmAdminConfiguration{}, nil)
		assert.Panics(t, func() {
			_, _, _ = m.GetConfigurations(context.Background(), "realmID")
		})
	})

	t.Run("Get configuration", func(t *testing.T) {
		mockComponent.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_, _ = m.GetConfiguration(ctx, realmID)
	})
	t.Run("Get configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetConfiguration(context.Background(), "realmID").Return(configuration.RealmConfiguration{}, nil).Times(1)
		var f = func() {
			_, _ = m.GetConfiguration(context.Background(), "realmID")
		}
		assert.Panics(t, f)
	})

	t.Run("Update configuration", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateConfiguration(ctx, "realmID", configuration.RealmConfiguration{}).Return(nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.StoreOrUpdateConfiguration(ctx, "realmID", configuration.RealmConfiguration{})
	})
	t.Run("Update configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateConfiguration(context.Background(), "realmID", configuration.RealmConfiguration{}).Return(nil).Times(1)
		var f = func() {
			_ = m.StoreOrUpdateConfiguration(context.Background(), "realmID", configuration.RealmConfiguration{})
		}
		assert.Panics(t, f)
	})

	t.Run("Get admin configuration with correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetAdminConfiguration(ctx, "realmID").Return(adminConfig, nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_, _ = m.GetAdminConfiguration(ctx, "realmID")
	})

	t.Run("Get admin configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetAdminConfiguration(context.Background(), "realmID").Return(adminConfig, nil).Times(1)
		var f = func() {
			_, _ = m.GetAdminConfiguration(context.Background(), "realmID")
		}
		assert.Panics(t, f)
	})

	t.Run("Update admin configuration with correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateAdminConfiguration(ctx, "realmID", gomock.Any()).Return(nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.StoreOrUpdateAdminConfiguration(ctx, "realmID", configuration.RealmAdminConfiguration{})
	})

	t.Run("Update configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateAdminConfiguration(context.Background(), "realmID", gomock.Any()).Return(nil).Times(1)
		assert.Panics(t, func() {
			_ = m.StoreOrUpdateAdminConfiguration(context.Background(), "realmID", configuration.RealmAdminConfiguration{})
		})
	})

	t.Run("Get Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groupNames).Return(dto.BackOfficeConfiguration{}, nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_, _ = m.GetBackOfficeConfiguration(ctx, realmID, groupNames)
	})
	t.Run("Get Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetBackOfficeConfiguration(context.Background(), realmID, groupNames).Return(dto.BackOfficeConfiguration{}, nil)
		assert.Panics(t, func() {
			_, _ = m.GetBackOfficeConfiguration(context.Background(), realmID, groupNames)
		})
	})

	t.Run("Delete Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, nil, nil).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, nil, nil)
	})
	t.Run("Delete Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().DeleteBackOfficeConfiguration(context.Background(), realmID, groupName, confType, nil, nil).Return(nil)
		assert.Panics(t, func() {
			_ = m.DeleteBackOfficeConfiguration(context.Background(), realmID, groupName, confType, nil, nil)
		})
	})
	t.Run("Insert Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, realmID, groupNames).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, realmID, groupNames)
	})
	t.Run("Insert Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().InsertBackOfficeConfiguration(context.Background(), realmID, groupName, confType, realmID, groupNames).Return(nil)
		assert.Panics(t, func() {
			_ = m.InsertBackOfficeConfiguration(context.Background(), realmID, groupName, confType, realmID, groupNames)
		})
	})

	t.Run("Get Authorization with correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().AuthorizationExists(ctx, realmID, groupNames[0], realmID, gomock.Any(), action).Return(true, nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_, _ = m.AuthorizationExists(ctx, realmID, groupNames[0], realmID, &groupNames[1], action)
	})

	t.Run("Get Authorization without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().AuthorizationExists(context.Background(), realmID, groupNames[0], realmID, gomock.Any(), action).Return(true, nil).Times(1)
		var f = func() {
			_, _ = m.AuthorizationExists(context.Background(), realmID, groupNames[0], realmID, &groupNames[1], action)
		}
		assert.Panics(t, f)
	})

	t.Run("Delete Authorization", func(t *testing.T) {
		mockComponent.EXPECT().DeleteAuthorization(ctx, realmID, groupNames[0], realmID, gomock.Any(), action).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.DeleteAuthorization(ctx, realmID, groupNames[0], realmID, &groupNames[1], action)
	})

	t.Run("Delete Authorization without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().DeleteAuthorization(context.Background(), realmID, groupNames[0], realmID, gomock.Any(), action).Return(nil)
		assert.Panics(t, func() {
			_ = m.DeleteAuthorization(context.Background(), realmID, groupNames[0], realmID, &groupNames[1], action)
		})
	})

	t.Run("Clean every realms Authorization", func(t *testing.T) {
		mockComponent.EXPECT().CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupNames[0], action).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupNames[0], action)
	})

	t.Run("Clean every realms Authorization without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().CleanAuthorizationsActionForEveryRealms(context.Background(), realmID, groupNames[0], action).Return(nil)
		assert.Panics(t, func() {
			_ = m.CleanAuthorizationsActionForEveryRealms(context.Background(), realmID, groupNames[0], action)
		})
	})

	t.Run("Clean realm Authorization", func(t *testing.T) {
		mockComponent.EXPECT().CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupNames[0], action).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		_ = m.CleanAuthorizationsActionForEveryRealms(ctx, realmID, groupNames[0], action)
	})

	t.Run("Clean realm Authorization without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().CleanAuthorizationsActionForRealm(context.Background(), realmID, groupNames[0], realmID, action).Return(nil)
		assert.Panics(t, func() {
			_ = m.CleanAuthorizationsActionForRealm(context.Background(), realmID, groupNames[0], realmID, action)
		})
	})
}
