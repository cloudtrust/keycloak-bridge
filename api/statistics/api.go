package apistatistics

import (
	"database/sql"

	kc "github.com/cloudtrust/keycloak-client/v2"
)

// RegExp for parameters of statistics API
const (
	RegExpPeriod          = `^hours|days|months$`
	RegExpNumber          = `^\d+$`
	RegExpTimeshift       = `^[+-]\d{1,4}$`
	RegExpTwoDigitsNumber = `^\d{1,2}$`
)

// ActionRepresentation struct
type ActionRepresentation struct {
	Name  *string `json:"name"`
	Scope *string `json:"scope"`
}

// IdentificationStatisticsRepresentation elements returned by GetStatistics
type IdentificationStatisticsRepresentation struct {
	VideoIdentifications    int `json:"videoIdentifications"`
	PhysicalIdentifications int `json:"physicalIdentifications"`
	AutoIdentifications     int `json:"autoIdentifications"`
	BasicIdentifications    int `json:"basicIdentifications"`
}

// StatisticsConnectionsRepresentation are elements used in StatisticsRepresentation
type StatisticsConnectionsRepresentation struct {
	LastTwelveHours int64 `json:"lastTwelveHours"`
	LastDay         int64 `json:"lastDay"`
	LastWeek        int64 `json:"lastWeek"`
	LastMonth       int64 `json:"lastMonth"`
	LastYear        int64 `json:"lastYear"`
}

// StatisticsUsersRepresentation elements returned by GetStatisticsUsers
type StatisticsUsersRepresentation struct {
	Total    int64 `json:"total"`
	Disabled int64 `json:"disabled"`
	Inactive int64 `json:"inactive"`
}

// DbConnectionRepresentation is a non serializable StatisticsConnectionRepresentation read from database
type DbConnectionRepresentation struct {
	Date   sql.NullString
	Result sql.NullString
	User   sql.NullString
	IP     string
}

// ConvertToAPIStatisticsUsers converts users statistics from KC model to API one
func ConvertToAPIStatisticsUsers(statistics kc.StatisticsUsersRepresentation) StatisticsUsersRepresentation {
	var statisticsAPI = StatisticsUsersRepresentation{}

	statisticsAPI.Total = statistics.Total
	statisticsAPI.Disabled = statistics.Disabled
	statisticsAPI.Inactive = statistics.Inactive

	return statisticsAPI
}
