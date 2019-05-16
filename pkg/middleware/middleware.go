package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
)

// MakeHTTPTracingMW try to extract an existing span from the HTTP headers. It it exists, we
// continue the span, if not we create a new one.
func MakeHTTPTracingMW(tracer opentracing.Tracer, componentName, operationName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var sc, err = tracer.Extract(opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(r.Header))

			var span opentracing.Span
			if err != nil {
				span = tracer.StartSpan(operationName)
			} else {
				span = tracer.StartSpan(operationName, opentracing.ChildOf(sc))
			}
			defer span.Finish()

			// Set tags.
			otag.Component.Set(span, componentName)
			span.SetTag("transport", "http")
			otag.SpanKindRPCServer.Set(span)

			next.ServeHTTP(w, r.WithContext(opentracing.ContextWithSpan(r.Context(), span)))
		})
	}
}

// MakeEndpointLoggingMW makes a logging middleware.
func MakeEndpointLoggingMW(logger log.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			logger.Log("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))
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
				h.With("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string)).Observe(time.Since(begin).Seconds())
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

				span.SetTag("correlation_id", ctx.Value(cs.CtContextCorrelationID).(string))

				ctx = opentracing.ContextWithSpan(ctx, span)
			}
			return next(ctx, request)
		}
	}
}

func httpErrorHandler(_ context.Context, statusCode int, err error, w http.ResponseWriter) {
	w.WriteHeader(statusCode)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var reply, _ = json.MarshalIndent(map[string]string{"error": err.Error()}, "", "  ")
	w.Write(reply)
}
