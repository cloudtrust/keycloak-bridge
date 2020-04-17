package event

import (
	"context"

	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/metrics"
	influx "github.com/influxdata/influxdb/client/v2"
)

// ConsoleModule is the interface of the console module.
type ConsoleModule interface {
	Print(context.Context, map[string]string) error
}

type consoleModule struct {
	logger log.Logger
}

// NewConsoleModule returns a Console module.
func NewConsoleModule(logger log.Logger) ConsoleModule {
	return &consoleModule{
		logger: logger,
	}
}

func (cm *consoleModule) Print(ctx context.Context, m map[string]string) error {
	// Log
	for k, v := range m {
		cm.logger.Info(ctx, k, v)
	}
	return nil
}

// StatisticModule is the interface of the keycloak statistic module.
type StatisticModule interface {
	Stats(context.Context, map[string]string) error
}

// Influx is the influx DB interface.
type Influx interface {
	Write(bp influx.BatchPoints) error
	Close()
}

type statisticModule struct {
	influx metrics.Metrics
}

//NewStatisticModule returns a Statistic module.
func NewStatisticModule(influx metrics.Metrics) StatisticModule {
	return &statisticModule{
		influx: influx,
	}
}

func (sm *statisticModule) Stats(ctx context.Context, m map[string]string) error {
	// Create a point and add to batch
	var tags = map[string]string{"type": m["type"], "realm": m["realmId"], "userId": m["userId"]}
	var fields = map[string]interface{}{
		"uid": m["uid"],
	}
	return sm.influx.Stats(ctx, "event_statistics", tags, fields)
}
