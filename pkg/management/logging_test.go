package management

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/dto"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/pkg/management/mock"
	"github.com/golang/mock/gomock"
)

func TestComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewConfigurationDBModule(mockCtrl)
	var mockLogger = mock.NewLogger(mockCtrl)

	var m = MakeConfigurationDBModuleLoggingMW(mockLogger)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), cs.CtContextCorrelationID, corrID)

	// Get configuration.
	mockComponent.EXPECT().GetConfiguration(ctx, "realmID").Return(dto.RealmConfiguration{}, nil).Times(1)
	mockLogger.EXPECT().Info("method", "GetConfiguration", "args", "realmID", "took", gomock.Any()).Return(nil).Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Update configuration.
	mockComponent.EXPECT().StoreOrUpdate(ctx, "realmID", dto.RealmConfiguration{}).Return(nil).Times(1)
	mockLogger.EXPECT().Info("method", "StoreOrUpdate", "args", "realmID", dto.RealmConfiguration{}, "took", gomock.Any()).Return(nil).Times(1)
	m.StoreOrUpdate(ctx, "realmID", dto.RealmConfiguration{})
}
