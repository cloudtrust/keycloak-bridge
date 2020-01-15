package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	errorhandler "github.com/cloudtrust/common-service/errors"
	msg "github.com/cloudtrust/keycloak-bridge/internal/messages"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetActions                      endpoint.Endpoint
	GetStatistics                   endpoint.Endpoint
	GetStatisticsUsers              endpoint.Endpoint
	GetStatisticsAuthenticators     endpoint.Endpoint
	GetStatisticsAuthentications    endpoint.Endpoint
	GetStatisticsAuthenticationsLog endpoint.Endpoint
	GetMigrationReport              endpoint.Endpoint
}

// MakeGetActionsEndpoint creates an endpoint for GetActions
func MakeGetActionsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return ec.GetActions(ctx)
	}
}

// MakeGetStatisticsEndpoint makes the statistic summary endpoint.
func MakeGetStatisticsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatistics(ctx, m["realm"])
	}
}

// MakeGetStatisticsUsersEndpoint makes the statistic users summary endpoint.
func MakeGetStatisticsUsersEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsUsers(ctx, m["realm"])
	}
}

// MakeGetStatisticsAuthenticatorsEndpoint makes the statistic authenticators summary endpoint.
func MakeGetStatisticsAuthenticatorsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatisticsAuthenticators(ctx, m["realm"])
	}
}

// MakeGetStatisticsAuthenticationsEndpoint makes the statistic authentications per period summary endpoint.
func MakeGetStatisticsAuthenticationsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		if _, ok := m["unit"]; !ok {
			return nil, errorhandler.CreateMissingParameterError(msg.Unit)
		}
		var timeshift *string = nil
		if timeshiftStr, ok := m["timeshift"]; ok {
			timeshift = &timeshiftStr
		}
		return ec.GetStatisticsAuthentications(ctx, m["realm"], m["unit"], timeshift)
	}
}

// MakeGetStatisticsAuthenticationsLogEndpoint makes the statistic last authentications summary endpoint.
func MakeGetStatisticsAuthenticationsLogEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		_, ok := m["max"]
		if !ok {
			return nil, errorhandler.CreateMissingParameterError(msg.Max)
		}
		return ec.GetStatisticsAuthenticationsLog(ctx, m["realm"], m["max"])
	}
}

// MakeGetMigrationReportEndpoint makes the migration reporting endpoint.
func MakeGetMigrationReportEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetMigrationReport(ctx, m["realm"])
	}
}
