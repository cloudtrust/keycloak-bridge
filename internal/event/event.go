package event

import (
	"context"
	"time"
)

const (
	timeFormat = "2006-01-02 15:04:05.000"
)

// EventStorer interface of a
type EventStorer interface {
	Store(context.Context, map[string]string) error
}

// ReportEventDetails information of an event to be reported
type ReportEventDetails struct {
	details map[string]string
}

// CreateEvent create the generic event that contains the ct_event_type, origin and audit_time
func CreateEvent(apiCall string, origin string) ReportEventDetails {
	var event ReportEventDetails
	event.details = make(map[string]string)
	event.details["ct_event_type"] = apiCall
	event.details["origin"] = origin
	event.details["audit_time"] = time.Now().UTC().Format(timeFormat)

	return event
}

// AddEventValues enhance the event with more information
func (er *ReportEventDetails) AddEventValues(values ...string) {
	//add information to the event
	noTuples := len(values)
	for i := 0; i+1 < noTuples; i = i + 2 {
		er.details[values[i]] = values[i+1]
	}
}

// AddAgentDetails add details from the context
func (er *ReportEventDetails) AddAgentDetails(ctx context.Context) {
	//retrieve agent username
	er.details["agent_username"] = ctx.Value("username").(string)
	//retrieve agent user id - not yet implemented
	//to be uncommented once the ctx contains the userId value
	//er.details["userId"] = ctx.Value("userId").(string)
	//retrieve agent realm
	er.details["agent_realm_name"] = ctx.Value("realm").(string)
}

// Report Report the event into the specified reporter
func (er *ReportEventDetails) Report(ctx context.Context, eventStorer EventStorer) error {
	return eventStorer.Store(ctx, er.details)
}

// ReportEvent Report the event into the specified eventStorer
func ReportEvent(ctx context.Context, eventStorer EventStorer, apiCall string, origin string, values ...string) error {
	event := CreateEvent(apiCall, origin)
	event.AddAgentDetails(ctx)
	event.AddEventValues(values...)
	return event.Report(ctx, eventStorer)
}
