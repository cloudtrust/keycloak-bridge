package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetStatistics      endpoint.Endpoint
	GetMigrationReport endpoint.Endpoint
}

// MakeGetStatisticsEndpoint makes the statistic summary endpoint.
func MakeGetStatisticsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetStatistics(ctx, m["realm"])
	}
}

// MakeGetMigrationReportEndpoint makes the migration reporting endpoint.
func MakeGetMigrationReportEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		var m = req.(map[string]string)
		return ec.GetMigrationReport(ctx, m["realm"])
	}
}
