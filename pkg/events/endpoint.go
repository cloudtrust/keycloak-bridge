package events

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetEvents        endpoint.Endpoint
	GetEventsSummary endpoint.Endpoint
	GetUserEvents    endpoint.Endpoint
}

// MakeGetEventsEndpoint makes the events endpoint.
func MakeGetEventsEndpoint(ec EventsComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), "first", "max", "dateFrom", "dateTo", "realmTarget", "userID", "origin", "ctEventType")
		return ec.GetEvents(ctx, params)
	}
}

// MakeGetEventsSummaryEndpoint makes the events summary endpoint.
func MakeGetEventsSummaryEndpoint(ec EventsComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return ec.GetEventsSummary(ctx)
	}
}

// MakeGetUserEventsEndpoint makes the events summary endpoint.
func MakeGetUserEventsEndpoint(ec EventsComponent) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), "first", "max", "dateFrom", "dateTo", "realm", "realmTarget", "userID", "origin", "ctEventType")
		return ec.GetUserEvents(ctx, params)
	}
}

func filterParameters(allParams map[string]string, paramNames ...string) map[string]string {
	var res map[string]string
	res = make(map[string]string)
	for _, key := range paramNames {
		if val, ok := allParams[key]; ok {
			res[key] = val
		}
	}
	return res
}
