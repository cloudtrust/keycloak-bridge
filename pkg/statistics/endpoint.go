package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetActions                   endpoint.Endpoint
	GetStatisticsIdentifications endpoint.Endpoint
	GetStatisticsUsers           endpoint.Endpoint
	GetStatisticsAuthenticators  endpoint.Endpoint
	GetMigrationReport           endpoint.Endpoint
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return ec.GetActions(ctx)
	}
}

// MakeGetStatisticsIdentificationsEndpoint makes the identification statistic summary endpoint.
func MakeGetStatisticsIdentificationsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsIdentifications(ctx, m[prmRealm])
	}
}

// MakeGetStatisticsUsersEndpoint makes the statistic users summary endpoint.
func MakeGetStatisticsUsersEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsUsers(ctx, m[prmRealm])
	}
}

// MakeGetStatisticsAuthenticatorsEndpoint makes the statistic authenticators summary endpoint.
func MakeGetStatisticsAuthenticatorsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsAuthenticators(ctx, m[prmRealm])
	}
}

// MakeGetMigrationReportEndpoint makes the migration reporting endpoint.
func MakeGetMigrationReportEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetMigrationReport(ctx, m[prmRealm])
	}
}
