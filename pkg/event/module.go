package event

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,Influx=Influx,ESClient=ESClient github.com/cloudtrust/keycloak-bridge/pkg/event ConsoleModule,StatisticModule,Influx,ESClient

import (
	"context"
	"fmt"
	"time"

	"database/sql"

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
		mapCopy[k] = v
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

const (
	createDB    = `CREATE DATABASE IF NOT EXISTS audit-events; `
	createTable = `CREATE TABLE IF NOT EXISTS audit (
		audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		audit_time TIMESTAMP,
		origin VARCHAR(255),
		realm_name VARCHAR(255),
		agent_user_id VARCHAR(36),
		agent_username VARCHAR(255),
		user_id VARCHAR(36),
		username VARCHAR(255),
		ct_event_type VARCHAR(50),
		kc_event_type VARCHAR(50),
		kc_operation_type VARCHAR(50),
		client_id VARCHAR(255),
		additional_info TEXT,
		CONSTRAINT audit_pk PRIMARY KEY (audit_id)
	  );`
	insertEvent = `INSERT INTO audit (
		origin,
		realm_name,
		agent_user_id,
		agent_username,
		user_id,
		username,
		ct_event_type,
		kc_event_type,
		kc_operation_type,
		client_id,
		additional_info) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);`
)

type DBEvents interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// EventsDBModule is the interface of the audit events module.
type EventsDBModule interface {
	Store(context.Context, map[string]string) error
}

type eventsDBModule struct {
	db DBEvents
}

// NewConsoleModule returns a Console module.
func NewEventsDBModule(db DBEvents) EventsDBModule {
	db.Exec(createTable)
	return &eventsDBModule{
		db: db,
	}
}

func (cm *eventsDBModule) Store(_ context.Context, m map[string]string) error {

	//can the result be useful?
	fmt.Println("In the events module")
	fmt.Println(m)
	fmt.Println("This was the event")

	//res, errDB := cm.db.Exec("CREATE TABLE example ( id integer, data varchar(32) )")
	//fmt.Println(res)
	//fmt.Println(errDB)

	_, err := cm.db.Exec(insertEvent, "origin", "realm", "agent_user_id", "agent_username",
		"user_id", "username", "ct_event_type", "kc_event_type", "kc_op_type", "client_id", "")
	//fmt.Println(res.RowsAffected())
	if err != nil {
		return err
	}
	return nil
}
