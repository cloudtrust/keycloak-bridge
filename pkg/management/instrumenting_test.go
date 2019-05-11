package management

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
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

	// Get configuration.
	mockComponent.EXPECT().GetConfiguration(ctx, "realmID").Return("", nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Get configuration without correlation ID.
	mockComponent.EXPECT().GetConfiguration(context.Background(), "realmID").Return("", nil).Times(1)
	var f = func() {
		m.GetConfiguration(context.Background(), "realmID")
	}
	assert.Panics(t, f)

	// Update configuration.
	mockComponent.EXPECT().StoreOrUpdate(ctx, "realmID", "{}").Return(nil).Times(1)
	mockHistogram.EXPECT().With("correlation_id", corrID).Return(mockHistogram).Times(1)
	mockHistogram.EXPECT().Observe(gomock.Any()).Return().Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")

	// Update configuration without correlation ID.
	mockComponent.EXPECT().StoreOrUpdate(context.Background(), "realmID", "{}").Return(nil).Times(1)
	f = func() {
		m.StoreOrUpdate(context.Background(), "realmID", "{}")
	}
	assert.Panics(t, f)
}
