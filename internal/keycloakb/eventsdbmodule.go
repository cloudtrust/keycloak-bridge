package keycloakb

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/cloudtrust/common-service/database"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
)

// EventsDBModule is the interface of the audit events module.
type EventsDBModule interface {
	GetEventsCount(context.Context, map[string]string) (int, error)
	GetEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetLastConnection(context.Context, string) (int64, error)
	GetTotalConnectionsCount(context.Context, string, string) (int64, error)
}

type eventsDBModule struct {
	db database.CloudtrustDB
}

// NewEventsDBModule returns an events database module.
func NewEventsDBModule(db database.CloudtrustDB) EventsDBModule {
	return &eventsDBModule{
		db: db,
	}
}

type selectAuditEventsParameters struct {
	origin      interface{}
	realm       interface{}
	userID      interface{}
	ctEventType interface{}
	dateFrom    interface{}
	dateTo      interface{}
	first       interface{}
	max         interface{}
}

const (
	whereAuditEvents = `
	WHERE origin = IFNULL(?, origin)
	AND realm_name = IFNULL(?, realm_name)
	AND user_id = IFNULL(?, user_id)
	AND ct_event_type = IFNULL(?, ct_event_type)
	AND unix_timestamp(audit_time) between IFNULL(?, unix_timestamp(audit_time)) and IFNULL(?, unix_timestamp(audit_time))
	`

	selectAuditEventsStmt = `SELECT audit_id, unix_timestamp(audit_time), origin, realm_name, agent_user_id, agent_username, agent_realm_name,
	                            user_id, username, ct_event_type, kc_event_type, kc_operation_type, client_id, additional_info
		FROM audit ` + whereAuditEvents + `		
		ORDER BY audit_time DESC
		LIMIT ?, ?;
		`
	selectCountAuditEventsStmt        = `SELECT count(1) FROM audit ` + whereAuditEvents
	selectLastConnectionTimeStmt      = `SELECT ifnull(unix_timestamp(max(audit_time)), 0) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK'`
	selectConnectionsCount            = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' AND date_add(audit_time, INTERVAL ##INTERVAL##)>now()`
	selectAuditSummaryRealmStmt       = `SELECT distinct realm_name FROM audit;`
	selectAuditSummaryOriginStmt      = `SELECT distinct origin FROM audit;`
	selectAuditSummaryCtEventTypeStmt = `SELECT distinct ct_event_type FROM audit;`
)

func createAuditEventsParametersFromMap(m map[string]string) selectAuditEventsParameters {
	return selectAuditEventsParameters{
		origin:      getSQLParam(m, "origin", nil),
		realm:       getSQLParam(m, "realm", nil),
		userID:      getSQLParam(m, "userID", nil),
		ctEventType: getSQLParam(m, "ctEventType", nil),
		dateFrom:    getSQLParam(m, "dateFrom", nil),
		dateTo:      getSQLParam(m, "dateTo", nil),
		first:       getSQLParam(m, "first", 0),
		max:         getSQLParam(m, "max", 500),
	}
}

// GetEvents gets the count of events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEventsCount(_ context.Context, m map[string]string) (int, error) {
	params := createAuditEventsParametersFromMap(m)

	var count int
	row := cm.db.QueryRow(selectCountAuditEventsStmt, params.origin, params.realm, params.userID, params.ctEventType, params.dateFrom, params.dateTo)
	err := row.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetEvents gets the events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEvents(_ context.Context, m map[string]string) ([]api.AuditRepresentation, error) {
	var res = []api.AuditRepresentation{}
	params := createAuditEventsParametersFromMap(m)

	rows, err := cm.db.Query(selectAuditEventsStmt, params.origin, params.realm, params.userID, params.ctEventType, params.dateFrom, params.dateTo, params.first, params.max)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	for rows.Next() {
		var dba api.DbAuditRepresentation
		err = rows.Scan(&dba.AuditID, &dba.AuditTime, &dba.Origin, &dba.RealmName, &dba.AgentUserID, &dba.AgentUsername, &dba.AgentRealmName,
			&dba.UserID, &dba.Username, &dba.CtEventType, &dba.KcEventType, &dba.KcOperationType, &dba.ClientID, &dba.AdditionalInfo)
		if err != nil {
			return res, err
		}
		res = append(res, dba.ToAuditRepresentation())
	}

	// Return an error from rows if any error was encountered by Rows.Scan
	return res, rows.Err()
}

// GetEventsSummary gets all available values for Origins, Realms and CtEventTypes
func (cm *eventsDBModule) GetEventsSummary(_ context.Context) (api.EventSummaryRepresentation, error) {
	var res api.EventSummaryRepresentation
	var err error

	// Get realms
	res.Realms, err = cm.queryStringArray(selectAuditSummaryRealmStmt)
	if err == nil {
		// Get origins
		res.Origins, err = cm.queryStringArray(selectAuditSummaryOriginStmt)
	}
	if err == nil {
		// Get ct_event_types
		res.CtEventTypes, err = cm.queryStringArray(selectAuditSummaryCtEventTypeStmt)
	}
	return res, err
}

// GetLastConnection gets the time of last connection for the given realm
func (cm *eventsDBModule) GetLastConnection(_ context.Context, realmName string) (int64, error) {
	var res = int64(0)
	var row = cm.db.QueryRow(selectLastConnectionTimeStmt, realmName)
	var err = row.Scan(&res)
	return res, err
}

// GetTotalConnectionsCount gets the number of connection for the given realm during the specified duration
func (cm *eventsDBModule) GetTotalConnectionsCount(_ context.Context, realmName string, durationLabel string) (int64, error) {
	var matched, err = regexp.MatchString(`^\d+ [A-Za-z]+$`, durationLabel)
	if !matched || err != nil {
		return 0, errors.New("invalidDurationLabel")
	}
	var res = int64(0)
	var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsCount, "##INTERVAL##", durationLabel), realmName)
	err = row.Scan(&res)
	return res, err
}

func getSQLParam(m map[string]string, name string, defaultValue interface{}) interface{} {
	if value, ok := m[name]; ok {
		return value
	}
	return defaultValue
}

func (cm *eventsDBModule) queryStringArray(request string) ([]string, error) {
	var res []string
	rows, err := cm.db.Query(request)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		rows.Scan(&value)
		res = append(res, value)
	}

	return res, nil
}
