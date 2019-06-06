package statistics

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
)

// Endpoints exposed for path /events
type Endpoints struct {
	GetStatistics endpoint.Endpoint
}

// MakeGetStatisticsEndpoint makes the events summary endpoint.
func MakeGetStatisticsEndpoint(ec Component) cs.Endpoint {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		return ec.GetStatistics(ctx, req.(map[string]string))
	}
}
