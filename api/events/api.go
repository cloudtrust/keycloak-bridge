package events_api

import "database/sql"

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

// DbAuditRepresentation is a non serializable AuditRepresentation read from database
type DbAuditRepresentation struct {
	AuditID         int64
	AuditTime       int64
	Origin          sql.NullString
	RealmName       sql.NullString
	AgentUserID     sql.NullString
	AgentUsername   sql.NullString
	AgentRealmName  sql.NullString
	UserID          sql.NullString
	Username        sql.NullString
	CtEventType     sql.NullString
	KcEventType     sql.NullString
	KcOperationType sql.NullString
	ClientID        sql.NullString
	AdditionalInfo  sql.NullString
}

// EventSummaryRepresentation elements returned by GetEventsSummary
type EventSummaryRepresentation struct {
	Origins      []string `json:"origins,omitempty"`
	Realms       []string `json:"realms,omitempty"`
	CtEventTypes []string `json:"ctEventTypes,omitempty"`
}

func ToString(sqlValue sql.NullString) string {
	if sqlValue.Valid {
		return sqlValue.String
	}
	return ""
}

// ToAuditRepresentation converts a DbAuditRepresentation to a serializable value
func (dba *DbAuditRepresentation) ToAuditRepresentation() AuditRepresentation {
	return AuditRepresentation{
		AuditID:         dba.AuditID,
		AuditTime:       dba.AuditTime,
		Origin:          ToString(dba.Origin),
		RealmName:       ToString(dba.RealmName),
		AgentUserID:     ToString(dba.AgentUserID),
		AgentUsername:   ToString(dba.AgentUsername),
		AgentRealmName:  ToString(dba.AgentRealmName),
		UserID:          ToString(dba.UserID),
		Username:        ToString(dba.Username),
		CtEventType:     ToString(dba.CtEventType),
		KcEventType:     ToString(dba.KcEventType),
		KcOperationType: ToString(dba.KcOperationType),
		ClientID:        ToString(dba.ClientID),
		AdditionalInfo:  ToString(dba.AdditionalInfo),
	}
}
