package event

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/cloudtrust/common-service/log"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestConsoleModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()

	var (
		uid = "uid"
		m   = map[string]string{
			"uid":           uid,
			"time":          "123314",
			"componentName": "component_name",
			"componentID":   "component_id",
		}
	)
	var consoleModule = NewConsoleModule(mockLogger)

	var err = consoleModule.Print(context.Background(), m)
	assert.Nil(t, err)
}

func TestStatisticsModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInflux = mock.NewMetrics(mockCtrl)

	var statisticModule = NewStatisticModule(mockInflux)
	mockInflux.EXPECT().Stats(gomock.Any(), "event_statistics", gomock.Any(), gomock.Any()).Times(1)
	var err = statisticModule.Stats(context.Background(), map[string]string{"type": "val"})
	assert.Nil(t, err)
}
