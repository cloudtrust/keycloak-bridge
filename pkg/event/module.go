package event

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,Influx=Influx,ESClient=ESClient github.com/cloudtrust/keycloak-bridge/pkg/event ConsoleModule,StatisticModule,Influx,ESClient

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
	influx "github.com/influxdata/influxdb/client/v2"
)

// ConsoleModule is the interface of the console module.
type ConsoleModule interface {
	Print(context.Context, map[string]string) error
}

// ESClient is the interface of the elasticsearch client.
type ESClient interface {
	IndexData(esIndex, esType, id, data interface{}) error
}

type consoleModule struct {
	esClient      ESClient
	esIndex       string
	componentName string
	componentID   string
	logger        log.Logger
}

// NewConsoleModule returns a Console module.
func NewConsoleModule(logger log.Logger, esc ESClient, esIndex, componentName, componentID string) ConsoleModule {
	return &consoleModule{
		esClient:      esc,
		esIndex:       esIndex,
		componentName: componentName,
		componentID:   componentID,
		logger:        logger,
	}
}

func (cm *consoleModule) Print(_ context.Context, m map[string]string) error {
	// Need to do a copy of the map to avoid data race
	var mapCopy = make(map[string]string)
	for k, v := range m {
		mapCopy[k]=v
	}

	// Add component infos in the map
	mapCopy["componentID"] = cm.componentID
	mapCopy["componentName"] = cm.componentName

	// Index data
	err := cm.esClient.IndexData(cm.esIndex, "audit", mapCopy["uid"], mapCopy)
	if err != nil {
		return err
	}

	// Log
	for k, v := range m {
		cm.logger.Log(k, v)
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
}

type statisticModule struct {
	influx           Influx
	batchPointConfig influx.BatchPointsConfig
}

//NewStatisticModule returns a Statistic module.
func NewStatisticModule(influx Influx, batchPointsConfig influx.BatchPointsConfig) StatisticModule {
	return &statisticModule{
		influx:           influx,
		batchPointConfig: batchPointsConfig,
	}
}

func (sm *statisticModule) Stats(_ context.Context, m map[string]string) error {

	// Create a new point batch
	var batchPoints influx.BatchPoints
	{
		var err error
		batchPoints, err = influx.NewBatchPoints(sm.batchPointConfig)
		if err != nil {
			return err
		}
	}

	// Create a point and add to batch
	var tags = map[string]string{"type": m["type"], "realm": m["realmId"], "userId": m["userId"]}
	var fields = map[string]interface{}{
		"uid": m["uid"],
	}

	var point *influx.Point
	{
		var err error
		point, err = influx.NewPoint("event_statistics", tags, fields, time.Now())
		if err != nil {
			return err
		}
		batchPoints.AddPoint(point)
	}

	// Write the batch
	var err = sm.influx.Write(batchPoints)
	if err != nil {
		return err
	}

	return nil
}
