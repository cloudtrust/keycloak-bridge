package middleware

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"

	opentracing "github.com/opentracing/opentracing-go"
)

type FlakiClient interface {
	GetCorrelationID() string
}

// MakeEndpointCorrelationIDMW makes a middleware that adds a correlation ID
// in the context if there is not already one.
func MakeEndpointCorrelationIDMW(flaki FlakiClient) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var id = ctx.Value("correlation_id")

			if id == nil {
				ctx = context.WithValue(ctx, "correlation_id", flaki.GetCorrelationID())
			}
			return next(ctx, req)
		}
	}
}

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

// MakeEndpointInstrumentingMW makes a middleware that measure the endpoints response time and
// send the metrics to influx DB.
func MakeEndpointInstrumentingMW(h metrics.Histogram) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			defer func(begin time.Time) {
				h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
			}(time.Now())
			return next(ctx, req)
		}
	}
}

// MakeEndpointTracingMW makes a middleware that handle the tracing with jaeger.
func MakeEndpointTracingMW(tracer opentracing.Tracer, operationName string) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			if span := opentracing.SpanFromContext(ctx); span != nil {
				span = tracer.StartSpan(operationName, opentracing.ChildOf(span.Context()))
				defer span.Finish()

				span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

				ctx = opentracing.ContextWithSpan(ctx, span)
			}
			return next(ctx, request)
		}
	}
}
