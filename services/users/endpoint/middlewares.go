package endpoints

import (
	"context"
	"strconv"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"

	stdopentracing "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
	otlog "github.com/opentracing/opentracing-go/log"
)

// /*
// Snowflake middleware. Currently an incrementing int. Not distributed. Sucks.
// */
// func MakeEndpointSnowflakeMiddleware(key interface{}) endpoint.Middleware {
// 	var snowflake = 0
// 	return func(next endpoint.Endpoint) endpoint.Endpoint {
// 		return func(ctx context.Context, req interface{}) (interface{}, error) {
// 			defer func() {
// 				snowflake++
// 			}()
// 			return next(context.WithValue(ctx, key, snowflake), req)
// 		}
// 	}
// }

func MakeTSMiddleware(h metrics.Histogram) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var correlationID = ctx.Value("id").(uint64)
			defer func(begin time.Time) {
				h.With("id", strconv.FormatUint(correlationID, 10)).Observe(time.Since(begin).Seconds())
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
			vaList = append(vaList, "id", ctx.Value("id"))
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

//MakeEndpointTracingMiddleware wraps Endpoint with a tracer
func MakeEndpointTracingMiddleware(tracer stdopentracing.Tracer, operationName string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			var span = stdopentracing.SpanFromContext(ctx)
			if span == nil {
				//create a new root span.
				span = tracer.StartSpan(operationName)
				span.SetTag("jaeger-debug-id", ctx.Value("id"))
				span.LogFields(otlog.String("operation", operationName),
					otlog.String("microservice_level", "endpoint"))

				otext.SpanKindRPCServer.Set(span)
				ctx = stdopentracing.ContextWithSpan(ctx, span)
				defer span.Finish()
				return next(ctx, request)
			}
			cspan := stdopentracing.StartSpan(operationName, stdopentracing.ChildOf(span.Context()))
			defer cspan.Finish()
			defer span.Finish()
			cspan.LogFields(otlog.String("operation", operationName),
				otlog.String("microservice_level", "endpoint"))

			otext.SpanKindRPCServer.Set(cspan)
			ctx = stdopentracing.ContextWithSpan(ctx, cspan)
			return next(ctx, request)
		}
	}
}
