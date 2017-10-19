package statistics

import (
	"fmt"
	"time"
	"github.com/influxdata/influxdb/client/v2"
)

/*
Keycloak statistics processor
 */
type KeycloakStatisticsProcessor interface{
	Stats(map[string]string) error
}

func NewKeycloakStatisticsProcessor(host string, username string, password string, database string) KeycloakStatisticsProcessor {
	return &keycloakStatisticsProcessor{
		config: client.HTTPConfig{
			Addr: host,
			Username: username,
			Password: password,
		},
		database: database,
	}
}

type keycloakStatisticsProcessor struct {
	config client.HTTPConfig
	database string
}

func (k *keycloakStatisticsProcessor) Stats(m map[string]string) error{

	c, err := client.NewHTTPClient(k.config)

	if err != nil {
		fmt.Println("Error creating InfluxDB Client: ", err.Error())
		return err
	}

	defer c.Close()


	// Create a new point batch
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  k.database,
		Precision: "s",
	})

	// Create a point and add to batch
	tags := map[string]string{"type": m["type"], "realm": m["realmId"], "userId": m["userId"]}
	fields := map[string]interface{}{
		"uid":   m["uid"],
	}
	pt, err := client.NewPoint("event_statistics", tags, fields, time.Now())
	if err != nil {
		fmt.Println("Error: ", err.Error())
	}
	bp.AddPoint(pt)

	// Write the batch
	// Write the batch
	err2 := c.Write(bp)
	if err2 != nil {
		fmt.Println("Error: ", err2.Error())
	}

	return nil
}