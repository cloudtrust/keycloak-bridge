package statistics

import (
	"fmt"
	"time"
	"testing"
	"github.com/influxdata/influxdb/client/v2"
)

func TestStatisticsModule(t *testing.T) {

	// Make client
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr: "http://172.17.0.2:8086",
		Username: "rpo",
		Password: "rpo",
	})
	if err != nil {
		fmt.Println("Error creating InfluxDB Client: ", err.Error())
	}
	defer c.Close()

	// Create a new point batch
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  "cloudtrust_grafana_test",
		Precision: "s",
	})

	// Create a point and add to batch
	tags := map[string]string{"cpu": "cpu-total"}
	fields := map[string]interface{}{
		"idle":   100.1,
		"system": 3.3,
		"user":   464.6,
	}
	pt, err := client.NewPoint("cpu_usage", tags, fields, time.Now())
	if err != nil {
		fmt.Println("Error: ", err.Error())
	}
	bp.AddPoint(pt)

	// Write the batch
	err2 := c.Write(bp)
	if err2 != nil {
		fmt.Println("Error: ", err2.Error())
	}

}


func TestStatisticsModule2(t *testing.T) {

	// Make client
	c, err := client.NewHTTPClient(client.HTTPConfig{
		Addr: "http://172.17.0.2:8086",
		Username: "rpo",
		Password: "rpo",
	})
	if err != nil {
		fmt.Println("Error creating InfluxDB Client: ", err.Error())
	}
	defer c.Close()

	// Create a new point batch
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  "cloudtrust_grafana_test",
		Precision: "s",
	})

	// Create a point and add to batch
	tags := map[string]string{"event": "login", "realm": "realmId",}
	fields := map[string]interface{}{
		"connexion":   1,
	}
	pt, err := client.NewPoint("event_stat", tags, fields, time.Now())
	if err != nil {
		fmt.Println("Error: ", err.Error())
	}
	bp.AddPoint(pt)

	// Write the batch
	err2 := c.Write(bp)
	if err2 != nil {
		fmt.Println("Error: ", err2.Error())
	}

}