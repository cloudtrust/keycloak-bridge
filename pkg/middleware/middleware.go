package middleware

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger
//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram
//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext
//go:generate mockgen -destination=./mock/eventComponent.go -package=mock -mock_names=MuxComponent=MuxComponent,Component=EventComponent,AdminComponent=AdminEventComponent github.com/cloudtrust/keycloak-bridge/pkg/event MuxComponent,Component,AdminComponent
//go:generate mockgen -destination=./mock/healthComponent.go -package=mock -mock_names=Component=HealthComponent github.com/cloudtrust/keycloak-bridge/pkg/health Component
//go:generate mockgen -destination=./mock/flakiClient.go -package=mock -mock_names=FlakiClient=FlakiClient github.com/cloudtrust/keycloak-bridge/pkg/flaki/fb FlakiClient
//go:generate mockgen -destination=./mock/grpc.go -package=mock -mock_names=Handler=Handler github.com/go-kit/kit/transport/grpc Handler

import (
	"context"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	"github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"
	"google.golang.org/grpc/metadata"
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

type grpcTracingMW struct {
	tracer        opentracing.Tracer
	componentName string
	operationName string
	next          grpc_transport.Handler
}

// MakeGRPCTracingMW makes a tracing middleware at transport level.
func MakeGRPCTracingMW(tracer opentracing.Tracer, componentName, operationName string) func(grpc_transport.Handler) grpc_transport.Handler {
	return func(next grpc_transport.Handler) grpc_transport.Handler {
		return &grpcTracingMW{
			tracer:        tracer,
			componentName: componentName,
			operationName: operationName,
			next:          next,
		}
	}
}

// ServeGRPC try to extract an existing span from the GRPC metadata. It it exists, we
// continue the span, if not we create a new one.
func (m *grpcTracingMW) ServeGRPC(ctx context.Context, req interface{}) (context.Context, interface{}, error) {
	var md, _ = metadata.FromIncomingContext(ctx)

	// Extract metadata.
	var carrier = make(opentracing.TextMapCarrier)
	for k, v := range md {
		carrier.Set(k, v[0])
	}

	var sc, err = m.tracer.Extract(opentracing.TextMap, carrier)
	var span opentracing.Span
	if err != nil {
		span = m.tracer.StartSpan(m.operationName)
	} else {
		span = m.tracer.StartSpan(m.operationName, opentracing.ChildOf(sc))
	}
	defer span.Finish()

	// Set tags.
	otag.Component.Set(span, m.componentName)
	span.SetTag("transport", "grpc")
	otag.SpanKindRPCServer.Set(span)

	return m.next.ServeGRPC(opentracing.ContextWithSpan(ctx, span), req)
}

// MakeEndpointCorrelationIDMW makes a middleware that adds a correlation ID
// in the context if there is not already one.
func MakeEndpointCorrelationIDMW(flaki fb.FlakiClient, tracer opentracing.Tracer) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var id = ctx.Value("correlation_id")

			if id == nil {
				if span := opentracing.SpanFromContext(ctx); span != nil {
					span = tracer.StartSpan("get_correlation_id", opentracing.ChildOf(span.Context()))
					otag.SpanKindRPCClient.Set(span)
					defer span.Finish()
					ctx = opentracing.ContextWithSpan(ctx, span)

					// Propagate the opentracing span.
					var carrier = make(opentracing.TextMapCarrier)
					var err = tracer.Inject(span.Context(), opentracing.TextMap, carrier)
					if err != nil {
						return nil, errors.Wrap(err, "could not inject tracer")
					}

					var md = metadata.New(carrier)
					ctx = metadata.NewOutgoingContext(ctx, md)
				}

				// Flaki request.
				var b = flatbuffers.NewBuilder(0)
				fb.FlakiRequestStart(b)
				b.Finish(fb.FlakiRequestEnd(b))

				var reply, err = flaki.NextValidID(ctx, b)
				var corrID string
				// If we cannot get ID from Flaki, we generate a random one.
				if err != nil {
					rand.Seed(time.Now().UnixNano())
					corrID = "degraded-" + strconv.FormatUint(rand.Uint64(), 10)
				} else {
					corrID = string(reply.Id())
				}

				ctx = context.WithValue(ctx, "correlation_id", corrID)
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
