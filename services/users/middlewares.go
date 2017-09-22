package users

import (
	"github.com/go-kit/kit/log"
	"context"
	"time"
	"github.com/go-kit/kit/endpoint"
)

/*
Service Middleware declarations
 */
type Middleware func(Service) Service

/*
Logging Middleware
 */
type serviceLoggingMiddleware struct {
	log log.Logger
	next Service
}

/*
serviceLoggingMiddleware implements Service
 */
func (s *serviceLoggingMiddleware)GetUsers(ctx context.Context, realm string) (<-chan string, <-chan error) {
	defer func(begin time.Time) {
		s.log.Log("method", "GetUsers", "realm", realm, "took", time.Since(begin))
	}(time.Now())
	return s.next.GetUsers(ctx, realm)
}

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

/*
Logging middleware for backend services.
 */
func MakeServiceLoggingMiddleware(log log.Logger) Middleware {
	return func(next Service) Service{
		return &serviceLoggingMiddleware {
			log: log,
			next: next,
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
			va_list = append(va_list,"err", err, )
			for _, key := range keys {
				va_list = append(va_list, key, ctx.Value(key))
			}
			defer func(begin time.Time) {
				va_list=append(va_list, "took", time.Since(begin))
				logger.Log(va_list...)
			}(time.Now())
			return next(ctx, req)
		}
	}
}