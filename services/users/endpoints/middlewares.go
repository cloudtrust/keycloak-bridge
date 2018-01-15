package endpoints

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
)

/*
Snowflake middleware. Currently an incrementing int. Not distributed. Sucks.
*/
func MakeEndpointSnowflakeMiddleware(key interface{}) endpoint.Middleware {
	var snowflake = 0
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			defer func() {
				snowflake++
			}()
			return next(context.WithValue(ctx, key, snowflake), req)
		}
	}
}

func MakeTSMiddleware(h metrics.Histogram) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			defer func(begin time.Time) {
				h.Observe(time.Since(begin).Seconds())
			}(time.Now())
			return next(ctx, req)
		}
	}
}

/*
Logging Middleware for Endpoints.
*/
func MakeEndpointLoggingMiddleware(logger log.Logger, keys ...interface{}) endpoint.Middleware {

	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (resp interface{}, err error) {
			var vaList []interface{}
			vaList = append(vaList, "err", err)
			for _, key := range keys {
				vaList = append(vaList, key, ctx.Value(key))
			}
			defer func(begin time.Time) {
				vaList = append(vaList, "took", time.Since(begin))
				logger.Log(vaList...)
			}(time.Now())
			return next(ctx, req)
		}
	}
}
