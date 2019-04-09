package event

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=ConsoleModule=ConsoleModule,StatisticModule=StatisticModule,EventsDBModule=EventsDBModule,Influx=Influx,DBEvents=DBEvents github.com/cloudtrust/keycloak-bridge/pkg/event ConsoleModule,StatisticModule,EventsDBModule,Influx,DBEvents

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
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

	// if ctEventType is not "", then record the events in MariaDB
	// otherwise, do nothing
	if m["ct_event_type"] == "" {
		return nil
	}

	origin := "keycloak" // for the moment only events of Keycloak
	realmName := m["realmId"]
	//agentUserID - userId of who is performing an action
	agentUserID := m["userId"]
	//agentUsername - username of who is performing an action
	agentUsername := m["username"] // normally, username can be found in the details key of the map
	//agentRealmName - realm of who is performing an action
	agentRealmName := "" // found in authdetails
	//userID - ID of the user that is impacted by the action
	userID := "" // found in authdetails, in resourcePath
	//username - username of the user that is impacted by the action
	username := "" //
	// ctEventType that  is established before at the component level
	ctEventType := m["ct_event_type"]
	// kcEventType corresponds to keycloak event type
	kcEventType := m["type"]
	// kcOperationType - operation type of the event that comes from Keycloak
	kcOperationType := m["operationType"]
	// Id of the client
	clientID := m["clientId"]

	//userId is in the resourcePath
	if resourcePath, ok := m["resourcePath"]; ok {
		reg := regexp.MustCompile(`[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}`)
		if strings.HasPrefix(resourcePath, "users") {
			userID = string(reg.Find([]byte(resourcePath)))
		}
	}

	// put all the other details of the events in additionInfo column of the DB
	var infoMap map[string]string
	infoMap = make(map[string]string)
	for k, v := range m {
		// exclude all the event details that are already inserted in the DB
		if k != "realmId" && k != "userId" && k != "type" && k != "operationType" && k != "clientId" && k != "details" && k != "ct_event_type" && k != "username" && k != "authDetails" {
			infoMap[k] = v
		}
	}

	//check if  the key details is present
	if details, ok := m["details"]; ok {
		eventDetails := []byte(details)
		var f map[string]string
		err := json.Unmarshal(eventDetails, &f)

		if err != nil {
			return err
		}

		// in details part we can retrieve the username
		agentUsername = f["username"]

		for k, v := range f {
			if k != "username" {
				infoMap[k] = v
			}
		}

	}

	//check if the key authdetails is present
	if authDetails, ok := m["authDetails"]; ok {
		eventAuthDetails := []byte(authDetails)
		var h map[string]string
		err := json.Unmarshal(eventAuthDetails, &h)

		if err != nil {
			return err
		}

		// in authdetails part we can retrieve the client id, agent realm id, agent user id
		for k, v := range h {
			switch {
			case k == "clientId" && clientID == "":
				clientID = h["clientId"]
			case k == "userId" && agentUserID == "":
				agentUserID = h["userId"]
			case k == "realmId" && agentRealmName == "":
				agentRealmName = h["realmId"]
			default:
				infoMap[k] = v
			}
		}
	}

	infos, err := json.Marshal(infoMap)
	if err != nil {
		return err
	}
	additionalInfo := string(infos)

	//store the event in the DB
	_, err = cm.db.Exec(insertEvent, origin, realmName, agentUserID, agentUsername, agentRealmName, userID, username, ctEventType, kcEventType, kcOperationType, clientID, additionalInfo)

	if err != nil {
		return err
	}
	return nil

}
