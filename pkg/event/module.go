package event

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,Influx=Influx github.com/cloudtrust/keycloak-bridge/pkg/event ConsoleModule,StatisticModule,Influx

import (
	"context"
	"encoding/json"
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

type consoleModule struct {
	logger log.Logger
}

// NewConsoleModule returns a Console module.
func NewConsoleModule(logger log.Logger) ConsoleModule {
	return &consoleModule{
		logger: logger,
	}
}

func (cm *consoleModule) Print(_ context.Context, m map[string]string) error {
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
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

	// m["details"] is a map[string]string
	eventDetails := []byte(m["details"])
	var f map[string]string
	err := json.Unmarshal(eventDetails, &f)

	if err != nil {
		return err
	}

	// if ctEventType is not "", then record the events in MariaDB

	fmt.Println("The whole event is")
	fmt.Println(m)
	origin := "keycloak" // for the moment only events of Keycloak
	realmName := m["realmId"]
	agentUserID := ""   // no agents, only events from Keycloak
	agentUsername := "" // no agents, only events from Keycloak
	userID := m["userId"]
	username := f["username"] // username is in the details
	ctEventType := ""         // the ct event type needs to be established before
	kcEventType := m["type"]
	kcOperationType := m["operationType"]
	clientID := m["clientId"]

	// put all the other details of the events in additionInfo column of the DB
	var infoMap map[string]string
	infoMap = make(map[string]string)
	for k, v := range m {
		// exclude all the event details that are already inserted in the DB
		if k != "realmId" && k != "userId" && k != "type" && k != "operationType" && k != "clientId" && k != "details" {
			infoMap[k] = v
		}
	}
	for k, v := range f {
		if k != "username" {
			infoMap[k] = v
		}
	}
	infos, err := json.Marshal(infoMap)
	if err != nil {
		return err
	}
	additionalInfo := string(infos)

	_, err = cm.db.Exec(insertEvent, origin, realmName, agentUserID, agentUsername, userID, username, ctEventType, kcEventType, kcOperationType, clientID, additionalInfo)

	if err != nil {
		//TODO: how is this error treated further?
		return err
	}
	return nil
}
