package events_api

// AuditEventsRepresentation is the type of the GetEvents response
type AuditEventsRepresentation struct {
	Events []AuditRepresentation `json:"events"`
	Count  int                   `json:"count"`
}

// AuditRepresentation elements returned by GetEvents
type AuditRepresentation struct {
	AuditID         int64  `json:"auditId,omitempty"`
	AuditTime       int64  `json:"auditTime,omitempty"`
	Origin          string `json:"origin,omitempty"`
	RealmName       string `json:"realmName,omitempty"`
	AgentUserID     string `json:"agentUserId,omitempty"`
	AgentUsername   string `json:"agentUsername,omitempty"`
	AgentRealmName  string `json:"agentRealmName,omitempty"`
	UserID          string `json:"userId,omitempty"`
	Username        string `json:"username,omitempty"`
	CtEventType     string `json:"ctEventType,omitempty"`
	KcEventType     string `json:"kcEventType,omitempty"`
	KcOperationType string `json:"kcOperationType,omitempty"`
	ClientID        string `json:"clientId,omitempty"`
	AdditionalInfo  string `json:"additionalInfo,omitempty"`
}

// EventSummaryRepresentation elements returned by GetEventsSummary
type EventSummaryRepresentation struct {
	Origins      []string `json:"origins,omitempty"`
	Realms       []string `json:"realms,omitempty"`
	CtEventTypes []string `json:"ctEventTypes,omitempty"`
}

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
