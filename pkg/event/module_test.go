package event

import (
	"context"
	"testing"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
	influx "github.com/influxdata/influxdb/client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConsoleModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockES = mock.NewESClient(mockCtrl)

	var (
		esIndex = "index"
		esType  = "type"
		uid     = "uid"
		m       = map[string]string{
			"type":          esType,
			"uid":           uid,
			"componentName": "component_name",
			"componentID":   "component_id",
		}
	)
	var consoleModule = NewConsoleModule(mockLogger, mockES, "index", "component_name", "component_id")

	for k, v := range m {
		mockLogger.EXPECT().Log(k, v).Return(nil).Times(1)
	}

	mockES.EXPECT().IndexData(esIndex, esType, uid, m).Return(nil).Times(1)
	var err = consoleModule.Print(context.Background(), m)
	assert.Nil(t, err)
}

func TestStatisticsModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInflux = mock.NewInflux(mockCtrl)

	var batchPointsConfig = influx.BatchPointsConfig{
		Precision: "s",
		Database:  "db",
	}

	var statisticModule = NewStatisticModule(mockInflux, batchPointsConfig)
	mockInflux.EXPECT().Write(gomock.Any()).Return(nil).Times(1)
	var err = statisticModule.Stats(context.Background(), map[string]string{"key": "val"})
	assert.Nil(t, err)
}
