package keycloakb

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"

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

	t.Run("Get configuration", func(t *testing.T) {
		mockComponent.EXPECT().GetConfiguration(ctx, realmID).Return(configuration.RealmConfiguration{}, nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		m.GetConfiguration(ctx, realmID)
	})
	t.Run("Get configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetConfiguration(context.Background(), "realmID").Return(configuration.RealmConfiguration{}, nil).Times(1)
		var f = func() {
			m.GetConfiguration(context.Background(), "realmID")
		}
		assert.Panics(t, f)
	})

	t.Run("Update configuration", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateConfiguration(ctx, "realmID", configuration.RealmConfiguration{}).Return(nil).Times(1)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		m.StoreOrUpdateConfiguration(ctx, "realmID", configuration.RealmConfiguration{})
	})
	t.Run("Update configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().StoreOrUpdateConfiguration(context.Background(), "realmID", configuration.RealmConfiguration{}).Return(nil).Times(1)
		var f = func() {
			m.StoreOrUpdateConfiguration(context.Background(), "realmID", configuration.RealmConfiguration{})
		}
		assert.Panics(t, f)
	})

	t.Run("Get Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().GetBackOfficeConfiguration(ctx, realmID, groupNames).Return(dto.BackOfficeConfiguration{}, nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		m.GetBackOfficeConfiguration(ctx, realmID, groupNames)
	})
	t.Run("Get Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().GetBackOfficeConfiguration(context.Background(), realmID, groupNames).Return(dto.BackOfficeConfiguration{}, nil)
		assert.Panics(t, func() {
			m.GetBackOfficeConfiguration(context.Background(), realmID, groupNames)
		})
	})

	t.Run("Delete Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, nil, nil).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		m.DeleteBackOfficeConfiguration(ctx, realmID, groupName, confType, nil, nil)
	})
	t.Run("Delete Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().DeleteBackOfficeConfiguration(context.Background(), realmID, groupName, confType, nil, nil).Return(nil)
		assert.Panics(t, func() {
			m.DeleteBackOfficeConfiguration(context.Background(), realmID, groupName, confType, nil, nil)
		})
	})

	t.Run("Insert Back-office configuration", func(t *testing.T) {
		mockComponent.EXPECT().InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, realmID, groupNames).Return(nil)
		mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
		mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
		m.InsertBackOfficeConfiguration(ctx, realmID, groupName, confType, realmID, groupNames)
	})
	t.Run("Insert Back-office configuration without correlation ID", func(t *testing.T) {
		mockComponent.EXPECT().InsertBackOfficeConfiguration(context.Background(), realmID, groupName, confType, realmID, groupNames).Return(nil)
		assert.Panics(t, func() {
			m.InsertBackOfficeConfiguration(context.Background(), realmID, groupName, confType, realmID, groupNames)
		})
	})
}
