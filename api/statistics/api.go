package stats_api

import (
	"database/sql"

	api_events "github.com/cloudtrust/keycloak-bridge/api/events"
	kc "github.com/cloudtrust/keycloak-client"
)

// RegExp for parameters of statistics API
const (
	RegExpPeriod          = `^hours|days|months$`
	RegExpNumber          = `^\d+$`
	RegExpTimeshift       = `^[+-]\d{1,4}$`
	RegExpTwoDigitsNumber = `^\d{1,2}$`
)

// StatisticsRepresentation elements returned by GetStatistics
type StatisticsRepresentation struct {
	LastConnection   int64                               `json:"lastConnection,omitempty"`
	TotalConnections StatisticsConnectionsRepresentation `json:"totalConnections,omitempty"`
}

// StatisticsConnectionsRepresentation are elements used in StatisticsRepresentation
type StatisticsConnectionsRepresentation struct {
	LastTwelveHours int64 `json:"lastTwelveHours,omitempty"`
	LastDay         int64 `json:"lastDay,omitempty"`
	LastWeek        int64 `json:"lastWeek,omitempty"`
	LastMonth       int64 `json:"lastMonth,omitempty"`
	LastYear        int64 `json:"lastYear,omitempty"`
}

// StatisticsUsersRepresentation elements returned by GetStatisticsUsers
type StatisticsUsersRepresentation struct {
	Total    int64 `json:"total"`
	Disabled int64 `json:"disabled"`
	Inactive int64 `json:"inactive"`
}

// StatisticsConnectionRepresentation elements returned by GetStatisticsAuthenticationsLog
type StatisticsConnectionRepresentation struct {
	Date   string `json:"date"`
	Result string `json:"result"`
	User   string `json:"user"`
	IP     string `json:"IP"`
}

// DbConnectionRepresentation is a non serializable StatisticsConnectionRepresentation read from database
type DbConnectionRepresentation struct {
	Date   sql.NullString
	Result sql.NullString
	User   sql.NullString
	IP     string
}

// ToConnRepresentation converts a DbConnectionRepresentation to a serializable value
func (dbc *DbConnectionRepresentation) ToConnRepresentation() StatisticsConnectionRepresentation {
	return StatisticsConnectionRepresentation{
		Date:   api_events.ToString(dbc.Date),
		Result: api_events.ToString(dbc.Result),
		User:   api_events.ToString(dbc.User),
		IP:     dbc.IP,
	}
}

// ConvertToAPIStatisticsUsers converts users statistics from KC model to API one
func ConvertToAPIStatisticsUsers(statistics kc.StatisticsUsersRepresentation) StatisticsUsersRepresentation {
	var statisticsAPI = StatisticsUsersRepresentation{}

	statisticsAPI.Total = statistics.Total
	statisticsAPI.Disabled = statistics.Disabled
	statisticsAPI.Inactive = statistics.Inactive

	return statisticsAPI
}
