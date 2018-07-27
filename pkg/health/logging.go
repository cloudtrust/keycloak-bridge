package health

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
)

// MakeEndpointLoggingMW makes a logging middleware.
func MakeEndpointLoggingMW(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			defer func(begin time.Time) {
				logger.Log("correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
			}(time.Now())

			return next(ctx, req)
		}
	}
}

// Logging middleware at component level.
type componentLoggingMW struct {
	logger log.Logger
	next   HealthCheckers
}

// MakeComponentLoggingMW makes a logging middleware at component level.
func MakeComponentLoggingMW(logger log.Logger) func(HealthCheckers) HealthCheckers {
	return func(next HealthCheckers) HealthCheckers {
		return &componentLoggingMW{
			logger: logger,
			next:   next,
		}
	}
}

// componentLoggingMW implements Component.
func (m *componentLoggingMW) HealthChecks(ctx context.Context, req map[string]string) (json.RawMessage, error) {
	defer func(begin time.Time) {
		m.logger.Log("request", req, "correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
	}(time.Now())

	return m.next.HealthChecks(ctx, req)
}
