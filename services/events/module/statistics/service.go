package statistics

import (
	"time"

	influx_client "github.com/influxdata/influxdb/client/v2"
)

/*
KeycloakStatisticsProcessor interface
*/
type KeycloakStatisticsProcessor interface {
	Stats(map[string]string) error
}

//NewKeycloakStatisticsProcessor instantiates KeycloakStatisticsProcessor
func NewKeycloakStatisticsProcessor(influxClient influx_client.Client, batchPointsConfig influx_client.BatchPointsConfig) KeycloakStatisticsProcessor {
	return &keycloakStatisticsProcessor{
		clientInflux:     influxClient,
		batchPointConfig: batchPointsConfig,
	}
}

type keycloakStatisticsProcessor struct {
	clientInflux     influx_client.Client
	batchPointConfig influx_client.BatchPointsConfig
}

func (k *keycloakStatisticsProcessor) Stats(m map[string]string) error {

	// Create a new point batch
	var batchPoints influx_client.BatchPoints
	{
		var err error
		batchPoints, err = influx_client.NewBatchPoints(k.batchPointConfig)
		if err != nil {
			return err
		}
	}

	// Create a point and add to batch
	var tags = map[string]string{"type": m["type"], "realm": m["realmId"], "userId": m["userId"]}
	var fields = map[string]interface{}{
		"uid": m["uid"],
	}

	var point *influx_client.Point
	{
		var err error
		point, err = influx_client.NewPoint("event_statistics", tags, fields, time.Now())
		if err != nil {
			return err
		}
		batchPoints.AddPoint(point)
	}

	// Write the batch
	var err = k.clientInflux.Write(batchPoints)
	if err != nil {
		return err
	}

	return nil
}
