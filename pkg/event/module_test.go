package event

import (
	"context"
	"testing"

	influx "github.com/influxdata/influxdb/client/v2"
	"github.com/stretchr/testify/assert"
)

func TestConsoleModule(t *testing.T) {
	var mockLogger = &mockLogger{called: false}

	var consoleModule = NewConsoleModule(mockLogger)
	assert.False(t, mockLogger.called)
	var err = consoleModule.Print(context.Background(), map[string]string{"key": "val"})
	assert.Nil(t, err)
	assert.True(t, mockLogger.called)
}

func TestStatisticsModule(t *testing.T) {
	var mockInflux = &mockInflux{called: false}

	var batchPointsConfig = influx.BatchPointsConfig{
		Precision: "s",
		Database:  "db",
	}

	var statisticModule = NewStatisticModule(mockInflux, batchPointsConfig)
	assert.False(t, mockInflux.called)
	var err = statisticModule.Stats(context.Background(), map[string]string{"key": "val"})
	assert.Nil(t, err)
	assert.True(t, mockInflux.called)
}

// Mock Influx client.
type mockInflux struct {
	called bool
}

func (i *mockInflux) Write(bp influx.BatchPoints) error {
	i.called = true
	return nil
}

// Mock ConsoleModule.
type mockConsoleModule struct {
	called bool
}

func (m *mockConsoleModule) Print(context.Context, map[string]string) error {
	m.called = true
	return nil
}

// Mock StatisticModule
type mockStatisticModule struct {
	called bool
}

func (m *mockStatisticModule) Stats(context.Context, map[string]string) error {
	m.called = true
	return nil
}
