package keycloakb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudtrust/common-service/database/sqltypes"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	api_stat "github.com/cloudtrust/keycloak-bridge/api/statistics"
	msg "github.com/cloudtrust/keycloak-bridge/internal/constants"
)

// EventsDBModule is the interface of the audit events module.
type EventsDBModule interface {
	GetEventsCount(context.Context, map[string]string) (int, error)
	GetEvents(context.Context, map[string]string) ([]api.AuditRepresentation, error)
	GetEventsSummary(context.Context) (api.EventSummaryRepresentation, error)
	GetLastConnection(context.Context, string) (int64, error)
	GetTotalConnectionsCount(context.Context, string, string) (int64, error)
	GetTotalConnectionsHoursCount(context.Context, string, *time.Location, int) ([][]int64, error)
	GetTotalConnectionsDaysCount(context.Context, string, *time.Location, int) ([][]int64, error)
	GetTotalConnectionsMonthsCount(context.Context, string, *time.Location, int) ([][]int64, error)
	GetLastConnections(context.Context, string, string) ([]api_stat.StatisticsConnectionRepresentation, error)
}

type eventsDBModule struct {
	db sqltypes.CloudtrustDB
}

// NewEventsDBModule returns an events database module.
func NewEventsDBModule(db sqltypes.CloudtrustDB) EventsDBModule {
	return &eventsDBModule{
		db: db,
	}
}

type selectAuditEventsParameters struct {
	clause    string
	word      string
	sqlParams []interface{}
	limitMin  interface{}
	limitMax  interface{}
}

const (
	sqlDateFormat = "2006-01-02 15:04:05"

	selectAuditEventsStmt = `SELECT audit_id, unix_timestamp(audit_time), origin, realm_name, agent_user_id, agent_username, agent_realm_name,
	                            user_id, username, ct_event_type, kc_event_type, kc_operation_type, client_id, additional_info
		FROM audit `
	selectCountAuditEventsStmt        = `SELECT count(1) FROM audit `
	selectLastConnectionTimeStmt      = `SELECT ifnull(unix_timestamp(max(audit_time)), 0) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK'`
	selectAuditSummaryOriginStmt      = `SELECT distinct origin FROM audit;`
	selectAuditSummaryCtEventTypeStmt = `SELECT distinct ct_event_type FROM audit;`
	selectConnectionsCount            = `SELECT count(1) FROM audit WHERE realm_name=? AND ct_event_type='LOGON_OK' AND date_add(audit_time, INTERVAL ##INTERVAL##)>now()`
	selectConnectionsHoursCount       = `
			SELECT date_format(date_add(audit_time, INTERVAL ? MINUTE), '%H'), count(1)
			FROM audit
			WHERE realm_name=?
			  AND ct_event_type='LOGON_OK'
			  AND audit_time between date_add(?, INTERVAL -1 DAY) and ?
			GROUP by date_format(date_add(audit_time, INTERVAL ? MINUTE), '%Y-%m-%d %H')
			ORDER BY audit_time
	`
	selectConnectionsDaysCount = `
			SELECT date_format(date_add(audit_time, INTERVAL ? MINUTE), '%d'), count(1)
			FROM audit
			WHERE realm_name=?
			  AND ct_event_type='LOGON_OK' 
			  AND audit_time between date_add(?, INTERVAL -1 MONTH) and ?
			GROUP by date_format(date_add(audit_time, INTERVAL ? MINUTE), '%Y-%m-%d')
			ORDER BY audit_time
	`
	selectConnectionsMonthsCount = `
			SELECT date_format(date_add(audit_time, INTERVAL ? MINUTE), '%m'), count(1)
			FROM audit
			WHERE realm_name=?
			  AND ct_event_type='LOGON_OK'
			  AND audit_time between date_add(?, INTERVAL -12 MONTH) and ?
			GROUP by date_format(date_add(audit_time, INTERVAL ? MINUTE), '%Y-%m')
			ORDER BY audit_time
	`
	selectConnectionStmt = `SELECT unix_timestamp(audit_time), ct_event_type, username, additional_info 
							FROM audit WHERE realm_name=? AND (ct_event_type='LOGON_OK' OR ct_event_type='LOGON_ERROR') 	
							ORDER BY audit_time DESC
							LIMIT ?;
				`

	sqlWordWhere = "WHERE"
	sqlWordAnd   = "AND"
)

var (
	// Associate bridge parameter name to its matching SQL column name
	auditEventsBridgeToSQLParameters = map[string]string{
		"origin":      "origin",
		"realm":       "realm_name",
		"userID":      "user_id",
		"ctEventType": "ct_event_type",
		"exclude":     "-ct_event_type",
	}
)

func newSelectAuditEventsParameters(m map[string]string) (selectAuditEventsParameters, error) {
	var res = selectAuditEventsParameters{word: sqlWordWhere}
	for bridgeName, sqlName := range auditEventsBridgeToSQLParameters {
		if strings.HasPrefix(sqlName, "-") {
			res.addSQLStringExclude(m, bridgeName, sqlName[1:])
		} else {
			res.addSQLString(m, bridgeName, sqlName)
		}
	}
	res.addSQLDateRange(m, "dateFrom", "dateTo", "audit_time")
	res.addLimit(m, "first", 0, "max", 500)

	return res, nil
}

func (sp *selectAuditEventsParameters) addSQLString(m map[string]string, mapEntryName string, sqlFieldName string) {
	if value, ok := m[mapEntryName]; ok {
		sp.clause = fmt.Sprintf("%s %s %s = ?", sp.clause, sp.word, sqlFieldName)
		sp.sqlParams = append(sp.sqlParams, value)
		sp.word = sqlWordAnd
	}
}

func (sp *selectAuditEventsParameters) addSQLStringExclude(m map[string]string, mapEntryName string, sqlFieldName string) {
	if multipleValues, ok := m[mapEntryName]; ok {
		for _, value := range strings.Split(multipleValues, ",") {
			sp.clause = fmt.Sprintf("%s %s %s <> ?", sp.clause, sp.word, sqlFieldName)
			sp.sqlParams = append(sp.sqlParams, value)
			sp.word = sqlWordAnd
		}
	}
}

func (sp *selectAuditEventsParameters) addSQLDateRange(m map[string]string, dateFromName, dateToName, sqlFieldName string) {
	var valueFrom, hasFrom = m[dateFromName]
	var valueTo, hasTo = m[dateToName]
	if hasFrom {
		if hasTo {
			sp.clause = fmt.Sprintf("%s %s %s BETWEEN ? AND ?", sp.clause, sp.word, sqlFieldName)
			sp.sqlParams = append(sp.sqlParams, toTime(valueFrom), toTime(valueTo))
		} else {
			sp.clause = fmt.Sprintf("%s %s %s >= ?", sp.clause, sp.word, sqlFieldName)
			sp.sqlParams = append(sp.sqlParams, toTime(valueFrom))
		}
	} else if hasTo {
		sp.clause = fmt.Sprintf("%s %s %s <= ?", sp.clause, sp.word, sqlFieldName)
		sp.sqlParams = append(sp.sqlParams, toTime(valueTo))
	} else {
		return
	}
	sp.word = sqlWordAnd
}

func (sp *selectAuditEventsParameters) addLimit(m map[string]string, minLabel string, minValue int, maxLabel string, maxValue int) {
	sp.limitMin = minValue
	sp.limitMax = maxValue

	if value, ok := m[minLabel]; ok {
		sp.limitMin = value
	}
	if value, ok := m[maxLabel]; ok {
		sp.limitMax = value
	}
}

func (sp *selectAuditEventsParameters) queryCount(db sqltypes.CloudtrustDB) sqltypes.SQLRow {
	return db.QueryRow(selectCountAuditEventsStmt+sp.clause, sp.sqlParams...)
}

func (sp *selectAuditEventsParameters) queryRows(db sqltypes.CloudtrustDB) (sqltypes.SQLRows, error) {
	var allParams = append(sp.sqlParams, sp.limitMin, sp.limitMax)
	return db.Query(selectAuditEventsStmt+sp.clause+` ORDER BY audit_time DESC LIMIT ?, ?`, allParams...)
}

func toTime(unixTimestamp string) string {
	if ts, err := strconv.ParseInt(unixTimestamp, 10, 64); err == nil {
		return time.Unix(ts, 0).UTC().Format(sqlDateFormat)
	}
	return unixTimestamp
}

func createStats(size int, firstValue, minValue, maxValue int, descending bool) [][]int64 {
	var res = make([][]int64, size)
	var currentValue = firstValue

	for i := 0; i < size; i++ {
		res[i] = make([]int64, 2)
		res[i][0] = int64(currentValue)
		if currentValue == minValue {
			currentValue = maxValue
		} else {
			currentValue--
		}
	}

	if !descending {
		for i := 0; i < size/2; i++ {
			res[i][0], res[size-i-1][0] = res[size-i-1][0], res[i][0]
		}
	}

	return res
}

func (cm *eventsDBModule) executeConnectionsQuery(stats [][]int64, query string, realmName string, maxTime time.Time, minutesShift int) error {
	rows, err := cm.db.Query(query, minutesShift, realmName, maxTime, maxTime, minutesShift)
	if err != nil {
		return err
	}
	defer rows.Close()

	var unitConn int64
	var nbConns int64
	var nextIdx = 0

	for rows.Next() {
		err = rows.Scan(&unitConn, &nbConns)
		if err != nil {
			return err
		}
		for nextIdx < len(stats) && stats[nextIdx][0] != unitConn {
			nextIdx++
		}
		if nextIdx < len(stats) {
			stats[nextIdx][1] = nbConns
		}
		nextIdx++
	}

	return rows.Err()
}

// GetEvents gets the count of events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEventsCount(_ context.Context, m map[string]string) (int, error) {
	filter, err := newSelectAuditEventsParameters(m)
	if err != nil {
		return 0, err
	}

	row := filter.queryCount(cm.db)

	var count int
	err = row.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// GetEvents gets the events matching some criterias (dateFrom, dateTo, realm, ...)
func (cm *eventsDBModule) GetEvents(_ context.Context, m map[string]string) ([]api.AuditRepresentation, error) {
	var res = []api.AuditRepresentation{}
	filter, errParams := newSelectAuditEventsParameters(m)
	if errParams != nil {
		return nil, errParams
	}

	rows, err := filter.queryRows(cm.db)
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

	// Get origins
	res.Origins, err = cm.queryStringArray(selectAuditSummaryOriginStmt)

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
		return 0, errors.New(msg.MsgErrInvalidParam + "." + msg.DurationLabel)
	}
	var res = int64(0)
	var row = cm.db.QueryRow(strings.ReplaceAll(selectConnectionsCount, "##INTERVAL##", durationLabel), realmName)
	err = row.Scan(&res)
	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 24 hours, hour by hour
func (cm *eventsDBModule) GetTotalConnectionsHoursCount(_ context.Context, realmName string, location *time.Location, minutesShift int) ([][]int64, error) {
	var now = time.Now()
	var nowLocalized = now.In(location)
	var res = createStats(24, nowLocalized.Hour(), 0, 23, false)

	maxTime := NextHour(nowLocalized)
	err := cm.executeConnectionsQuery(res, selectConnectionsHoursCount, realmName, maxTime, minutesShift)

	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 30 days, day by day
func (cm *eventsDBModule) GetTotalConnectionsDaysCount(_ context.Context, realmName string, location *time.Location, minutesShift int) ([][]int64, error) {
	var now = time.Now()
	var nowLocalized = now.In(location)
	var maxDay = ThisMonth(nowLocalized).Add(-time.Hour).Day()
	var res = createStats(maxDay, nowLocalized.Day(), 1, maxDay, false)

	maxTime := NextDay(nowLocalized)
	err := cm.executeConnectionsQuery(res, selectConnectionsDaysCount, realmName, maxTime, minutesShift)

	return res, err
}

// GetTotalConnectionsHoursCount gets the number of connections for the given realm for the last 24 hours, hour by hour
func (cm *eventsDBModule) GetTotalConnectionsMonthsCount(_ context.Context, realmName string, location *time.Location, minutesShift int) ([][]int64, error) {
	var now = time.Now()
	var nowLocalized = now.In(location)
	var res = createStats(12, int(nowLocalized.Month()), 1, 12, false)

	maxTime := NextMonth(nowLocalized)
	err := cm.executeConnectionsQuery(res, selectConnectionsMonthsCount, realmName, maxTime, minutesShift)

	return res, err
}

// GetLastConnections gives information on the last authentications
func (cm *eventsDBModule) GetLastConnections(_ context.Context, realmName string, nbConnections string) ([]api_stat.StatisticsConnectionRepresentation, error) {

	var res = []api_stat.StatisticsConnectionRepresentation{}
	rows, err := cm.db.Query(selectConnectionStmt, realmName, nbConnections)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	for rows.Next() {
		var dbc api_stat.DbConnectionRepresentation
		var addInfos string
		err = rows.Scan(&dbc.Date, &dbc.Result, &dbc.User, &addInfos)
		if err != nil {
			return res, err
		}
		var infos map[string]string
		_ = json.Unmarshal([]byte(addInfos), &infos)
		dbc.IP = string(infos["ip_address"])
		res = append(res, dbc.ToConnRepresentation())
	}

	return res, err
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
