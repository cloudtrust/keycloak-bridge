package events

import (
	"context"
	"database/sql"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
)

// DBEvents is the interface to access the database
type DBEvents interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// EventsDBModule is the interface of the audit events module.
type EventsDBModule interface {
	GetEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
}

type eventsDBModule struct {
	db DBEvents
}

// NewEventsDBModule returns an events database module.
func NewEventsDBModule(db DBEvents) EventsDBModule {
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
	selectAuditEventsStmt = `SELECT audit_id, unix_timestamp(audit_time), origin, realm_name, agent_user_id, agent_username, agent_realm_name,
	                            user_id, username, ct_event_type, kc_event_type, kc_operation_type, client_id, additional_info
		FROM audit
		WHERE origin = IFNULL(?, origin)
		  AND realm_name = IFNULL(?, realm_name)
		  AND user_id = IFNULL(?, user_id)
		  AND ct_event_type = IFNULL(?, ct_event_type)
		  AND unix_timestamp(audit_time) between IFNULL(?, unix_timestamp(audit_time)) and IFNULL(?, unix_timestamp(audit_time))
		ORDER BY audit_time DESC
		LIMIT ?, ?;
		`

	selectAuditSummaryRealmStmt       = `SELECT distinct realm_name FROM audit;`
	selectAuditSummaryOriginStmt      = `SELECT distinct origin FROM audit;`
	selectAuditSummaryCtEventTypeStmt = `SELECT distinct ct_event_type FROM audit;`
)

// GetEvents gets the events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEvents(_ context.Context, m map[string]string) ([]api.AuditRepresentation, error) {
	var res []api.AuditRepresentation
	params := selectAuditEventsParameters{
		origin:      getSQLParam(m, "origin", nil),
		realm:       getSQLParam(m, "realm", nil),
		userID:      getSQLParam(m, "userID", nil),
		ctEventType: getSQLParam(m, "ctEventType", nil),
		dateFrom:    getSQLParam(m, "dateFrom", nil),
		dateTo:      getSQLParam(m, "dateTo", nil),
		first:       getSQLParam(m, "first", 0),
		max:         getSQLParam(m, "max", 500),
	}

	rows, err := cm.db.Query(selectAuditEventsStmt, params.origin, params.realm, params.userID, params.ctEventType, params.dateFrom, params.dateTo, params.first, params.max)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	for rows.Next() {
		var audit api.AuditRepresentation
		err = rows.Scan(&audit.AuditID, &audit.AuditTime, &audit.Origin, &audit.RealmName, &audit.AgentUserID, &audit.AgentUsername, &audit.AgentRealmName,
			&audit.UserID, &audit.Username, &audit.CtEventType, &audit.KcEventType, &audit.KcOperationType, &audit.ClientID, &audit.AdditionalInfo)
		if err != nil {
			return res, err
		}
		res = append(res, audit)
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
