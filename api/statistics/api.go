package stats_api

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
