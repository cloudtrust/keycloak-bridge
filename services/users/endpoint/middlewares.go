package endpoints

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	"google.golang.org/grpc/metadata"

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
			var md, _ = metadata.FromIncomingContext(ctx)
			//var correlationID, err = strconv.ParseInt(md["id"][0], 10, 64)
			//if err != nil {
			//	return nil, err
			//}
			defer func(begin time.Time) {
				h.With("id", md["id"][0]).Observe(time.Since(begin).Seconds())
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
			var md, _ = metadata.FromIncomingContext(ctx)
			var correlationID = md["id"][0]
			vaList = append(vaList, "id", correlationID)
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
			var md, _ = metadata.FromIncomingContext(ctx)
			var correlationID = md["id"][0]

			var span = stdopentracing.SpanFromContext(ctx)
			if span == nil {
				//create a new root span.
				span = tracer.StartSpan(operationName)
				span.SetTag("jaeger-debug-id", correlationID)
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
