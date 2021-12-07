package events

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetActions                  endpoint.Endpoint
	GetEvents                   endpoint.Endpoint
	GetEventsSummary            endpoint.Endpoint
	GetUserEvents               endpoint.Endpoint
	GetStatistics               endpoint.Endpoint
	GetStatisticsUsers          endpoint.Endpoint
	GetStatisticsAuthenticators endpoint.Endpoint
	//GetStatisticsAuthentications endpoint.Endpoint
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return ec.GetActions(ctx)
	}
}

// MakeGetEventsEndpoint makes the events endpoint.
func MakeGetEventsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), prmQueryFirst, prmQueryMax, prmQueryDateFrom, prmQueryDateTo, prmQueryTargetRealm, prmQueryOrigin, prmQueryCtEventType, prmQueryExclude)

		//Rewrite realmTarget into realm
		if value, ok := params[prmQueryTargetRealm]; ok {
			params[prmPathRealm] = value
			delete(params, prmQueryTargetRealm)
		}

		return ec.GetEvents(ctx, params)
	}
}

// MakeGetEventsSummaryEndpoint makes the events summary endpoint.
func MakeGetEventsSummaryEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return ec.GetEventsSummary(ctx)
	}
}

// MakeGetUserEventsEndpoint makes the events summary endpoint.
func MakeGetUserEventsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		params := filterParameters(req.(map[string]string), prmQueryFirst, prmQueryMax, prmQueryDateFrom, prmQueryDateTo, prmPathRealm, prmPathUserID, prmQueryOrigin, prmQueryCtEventType, prmQueryExclude)
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
