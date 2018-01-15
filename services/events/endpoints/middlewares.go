package endpoints

import (
	"github.com/go-kit/kit/endpoint"
	"time"
	"context"
	"github.com/go-kit/kit/log"
)

/*
MakeEndpointLoggingMiddleware returns the Logging Middleware for Endpoints.
 */
func MakeEndpointLoggingMiddleware(logger log.Logger, keys ...interface{}) endpoint.Middleware {

	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (resp interface{}, err error) {
			var vaList []interface{}
			vaList = append(vaList,"Method", "Endpoint", )
			vaList = append(vaList,"err", err, )
			for _, key := range keys {
				vaList = append(vaList, key, ctx.Value(key))
			}
			defer func(begin time.Time) {
				vaList = append(vaList, "took", time.Since(begin))
				logger.Log( vaList...)
			}(time.Now())
			return next(ctx, req)
		}
	}
}