package endpoints

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
)

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
			var va_list []interface{}
			va_list = append(va_list, "err", err)
			for _, key := range keys {
				va_list = append(va_list, key, ctx.Value(key))
			}
			defer func(begin time.Time) {
				va_list = append(va_list, "took", time.Since(begin))
				logger.Log(va_list...)
			}(time.Now())
			return next(ctx, req)
		}
	}
}
