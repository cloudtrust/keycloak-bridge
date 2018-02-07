package event

import (
	"testing"

	influx "github.com/influxdata/influxdb/client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConsoleModule(t *testing.T) {
	var mockLogger = &mockLogger{Called: false}

	var consoleModule = NewConsoleModule(mockLogger)
	assert.False(t, mockLogger.Called)
	var err = consoleModule.Print(map[string]string{"key": "val"})
	assert.Nil(t, err)
	assert.True(t, mockLogger.Called)
}

func TestStatisticsModule(t *testing.T) {
	var mockInflux = &mockInflux{Called: false}

	var batchPointsConfig = influx.BatchPointsConfig{
		Precision: "s",
		Database:  "db",
	}

	var statisticModule = NewStatisticModule(mockInflux, batchPointsConfig)
	assert.False(t, mockInflux.Called)
	var err = statisticModule.Stats(map[string]string{"key": "val"})
	assert.Nil(t, err)
	assert.True(t, mockInflux.Called)
}

// Mock Influx client.
type mockInflux struct {
	Called bool
}

func (i *mockInflux) Write(bp influx.BatchPoints) error {
	i.Called = true
	return nil
}
