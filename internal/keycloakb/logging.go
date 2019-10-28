package keycloakb

import (
	"context"
	"encoding/json"
)

// Logger interface for logging with level
type Logger interface {
	Debug(keyvals ...interface{}) error
	Info(keyvals ...interface{}) error
	Warn(keyvals ...interface{}) error
	Error(keyvals ...interface{}) error
}

// LogUnrecordedEvent logs the events that could not be reported in the DB
func LogUnrecordedEvent(ctx context.Context, logger Logger, eventName string, errorMessage string, values ...string) {
	if len(values)%2 != 0 {
		logger.Error("err", "When logging an unrecorded event the number of parameters should be even")
	}
	m := map[string]interface{}{"event_name": eventName}
	for i := 0; i < len(values); i += 2 {
		m[values[i]] = values[i+1]
	}
	eventJSON, errMarshal := json.Marshal(m)
	if errMarshal == nil {
		logger.Error("err", errorMessage, "event", string(eventJSON))
	} else {
		logger.Error("err", errorMessage)
	}
}
