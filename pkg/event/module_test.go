package event

import (
	"context"
	"testing"

	"encoding/json"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/mock"
	"github.com/golang/mock/gomock"
	influx "github.com/influxdata/influxdb/client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConsoleModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)

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

	for k, v := range m {
		mockLogger.EXPECT().Log(k, v).Return(nil).Times(1)
	}

	var err = consoleModule.Print(context.Background(), m)
	assert.Nil(t, err)
}

func TestStatisticsModuleWithMissingValues(t *testing.T) {
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
	var err = statisticModule.Stats(context.Background(), map[string]string{"type": "val"})
	assert.Nil(t, err)
}

func TestEventsDBModule(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewDBEvents(mockCtrl)

	mockDB.EXPECT().Exec(gomock.Any()).Return(nil, nil).AnyTimes()
	var eventsDBModule = NewEventsDBModule(mockDB)
	var err = eventsDBModule.Store(context.Background(), map[string]string{"type": "val"})
	assert.Nil(t, err)
}

func TestEventsDBModuleCTEvent(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockDB = mock.NewDBEvents(mockCtrl)

	mockDB.EXPECT().Exec(gomock.Any()).Return(nil, nil).AnyTimes()
	var eventsDBModule = NewEventsDBModule(mockDB)

	var ctEvent = make(map[string]string)
	ctEvent["ct_event_type"] = "LOGIN"
	ctEvent["realm_id"] = "dummyRealm"
	ctEvent["kc_event_type"] = "dummyType"
	ctEvent["kc_operation_type"] = "dummyOpType"
	ctEvent["client_id"] = "dummyClient"

	var details = make(map[string]string)
	details["resource_path"] = "users/dummyPath"
	details["error"] = ""
	detailsJson, _ := json.Marshal(details)
	ctEvent["additional_info"] = string(detailsJson)

	mockDB.EXPECT().Exec(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	var err = eventsDBModule.Store(context.Background(), ctEvent)
	assert.Nil(t, err)
}
