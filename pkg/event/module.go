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
		agent_realm_name VARCHAR(255),
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
		agent_realm_name,
		user_id,
		username,
		ct_event_type,
		kc_event_type,
		kc_operation_type,
		client_id,
		additional_info) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

	fmt.Println("The whole event is")
	fmt.Println(m)

	// if ctEventType is not "", then record the events in MariaDB
	if m["ct_event_type"] != "" {
		origin := "keycloak" // for the moment only eventss of Keycloak
		realmName := m["realmId"]
		agentUserID := ""    // no agents, only events from Keycloak
		agentUsername := ""  // no agents, only events from Keycloak
		agentRealmName := "" // realm of the agent
		userID := m["userId"]
		username := m["username"]         // normally, username is in the details
		ctEventType := m["ct_event_type"] // the ct event type is established before
		kcEventType := m["type"]
		kcOperationType := m["operationType"]
		clientID := m["clientId"]

		// put all the other details of the events in additionInfo column of the DB
		var infoMap map[string]string
		infoMap = make(map[string]string)
		for k, v := range m {
			// exclude all the event details that are already inserted in the DB
			if k != "realmId" && k != "userId" && k != "type" && k != "operationType" && k != "clientId" && k != "details" && k != "ct_event_type" && k != "username" {
				infoMap[k] = v
			}
		}

		//check if there is the key details
		if details, ok := m["details"]; ok {
			eventDetails := []byte(details)
			var f map[string]string
			err := json.Unmarshal(eventDetails, &f)

			if err != nil {
				fmt.Println(err)
				return err
			}

			// in details part we can retrieve the username
			username = f["username"]

			for k, v := range f {
				if k != "username" {
					infoMap[k] = v
				}
			}

		}

		//check if there is the key authdetails
		if authDetails, ok := m["authDetails"]; ok {
			eventAuthDetails := []byte(authDetails)
			var h map[string]string
			err := json.Unmarshal(eventAuthDetails, &h)

			if err != nil {
				fmt.Println(err)
				return err
			}

			// in authdetails part we can retrieve the client id, agent realm id, user id
			if clientID == "" {
				clientID = h["clientId"]
			}
			if userID == "" {
				userID = h["userId"]
			}
			if agentRealmName == "" {
				agentRealmName = h["realmId"]
			}

			for k, v := range h {
				if k != "clientId" && k != "userId" && k != "realmId" {
					infoMap[k] = v
				}
			}

		}

		infos, err := json.Marshal(infoMap)
		if err != nil {
			fmt.Println("Error in Marshalling the additional info")
			fmt.Println(err)
			return err
		}
		additionalInfo := string(infos)

		_, err = cm.db.Exec(insertEvent, origin, realmName, agentUserID, agentUsername, agentRealmName, userID, username, ctEventType, kcEventType, kcOperationType, clientID, additionalInfo)

		if err != nil {
			//TODO: how is this error treated further?
			fmt.Println(err)
			return err
		}
	}
	return nil
}
