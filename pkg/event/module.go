package event

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,EventsDBModule=EventsDBModule,Influx=Influx,DBEvents=DBEvents github.com/cloudtrust/keycloak-bridge/pkg/event ConsoleModule,StatisticModule,EventsDBModule,Influx,DBEvents

import (
	"context"
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
	createTable = `CREATE TABLE IF NOT EXISTS audit (
		audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		audit_time TIMESTAMP NULL,
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
		audit_time,
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
	//db.Exec(createTable)
	return &eventsDBModule{
		db: db,
	}
}

func (cm *eventsDBModule) Store(_ context.Context, m map[string]string) error {

	// if ctEventType is not "", then record the events in MariaDB
	// otherwise, do nothing
	if m["ct_event_type"] == "" {
		return nil
	}

	// the event was already formatted according to the DB structure already at the component level

	//auditTime - time of the event
	auditTime := m["audit_time"]
	// origin - the component that initiated the event
	origin := m["origin"]
	// realmName - realm name of the user that is impacted by the action
	realmName := m["realm_name"]
	//agentUserID - userId of who is performing an action
	agentUserID := m["agent_user_id"]
	//agentUsername - username of who is performing an action
	agentUsername := m["agent_username"]
	//agentRealmName - realm of who is performing an action
	agentRealmName := m["agent_realm_name"]
	//userID - ID of the user that is impacted by the action
	userID := m["user_id"]
	//username - username of the user that is impacted by the action
	username := m["username"]
	// ctEventType that  is established before at the component level
	ctEventType := m["ct_event_type"]
	// kcEventType corresponds to keycloak event type
	kcEventType := m["kc_event_type"]
	// kcOperationType - operation type of the event that comes from Keycloak
	kcOperationType := m["kc_operation_type"]
	// Id of the client
	clientID := m["client_id"]
	//additional_info - all the rest of the information from the event
	additionalInfo := m["additional_info"]

	//store the event in the DB
	_, err := cm.db.Exec(insertEvent, auditTime, origin, realmName, agentUserID, agentUsername, agentRealmName, userID, username, ctEventType, kcEventType, kcOperationType, clientID, additionalInfo)

	if err != nil {
		return err
	}
	return nil

}
