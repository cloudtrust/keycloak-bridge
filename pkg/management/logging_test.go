package management

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"

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
	mockComponent.EXPECT().GetConfiguration(ctx, "realmID").Return("", nil).Times(1)
	mockLogger.EXPECT().Log("method", "GetConfiguration", "args", "realmID", "took", gomock.Any()).Return(nil).Times(1)
	m.GetConfiguration(ctx, "realmID")

	// Update configuration.
	mockComponent.EXPECT().StoreOrUpdate(ctx, "realmID", "{}").Return(nil).Times(1)
	mockLogger.EXPECT().Log("method", "StoreOrUpdate", "args", "realmID", "{}", "took", gomock.Any()).Return(nil).Times(1)
	m.StoreOrUpdate(ctx, "realmID", "{}")
}
