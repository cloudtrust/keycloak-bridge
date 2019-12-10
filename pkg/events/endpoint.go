package events

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetEvents                   endpoint.Endpoint
	GetEventsSummary            endpoint.Endpoint
	GetUserEvents               endpoint.Endpoint
	GetStatistics               endpoint.Endpoint
	GetStatisticsUsers          endpoint.Endpoint
	GetStatisticsAuthenticators endpoint.Endpoint
	//GetStatisticsAuthentications endpoint.Endpoint
}

// MakeGetEventsEndpoint makes the events endpoint.
func MakeGetEventsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), "first", "max", "dateFrom", "dateTo", "realmTarget", "origin", "ctEventType", "exclude")

		//Rewrite realmTarget into realm
		if value, ok := params["realmTarget"]; ok {
			params["realm"] = value
			delete(params, "realmTarget")
		}

		return ec.GetEvents(ctx, params)
	}
}

// MakeGetEventsSummaryEndpoint makes the events summary endpoint.
func MakeGetEventsSummaryEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return ec.GetEventsSummary(ctx)
	}
}

// MakeGetUserEventsEndpoint makes the events summary endpoint.
func MakeGetUserEventsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), "first", "max", "dateFrom", "dateTo", "realm", "userID", "origin", "ctEventType")
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
