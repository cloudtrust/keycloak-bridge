package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/flaki/fb"
	"github.com/go-kit/kit/log"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	flatbuffers "github.com/google/flatbuffers/go"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"
	"google.golang.org/grpc/metadata"
)

// MakeHTTPCorrelationIDMW retrieve the correlation ID from the HTTP header 'X-Correlation-ID'.
// It there is no such header, it gets a correlation ID from Flaki.
// The Flaki request is traced.
func MakeHTTPCorrelationIDMW(flaki fb.FlakiClient, tracer opentracing.Tracer, logger log.Logger, componentName, componentID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			var correlationID = req.Header.Get("X-Correlation-ID")

			if correlationID == "" {
				var ctx = req.Context()
				var span = opentracing.SpanFromContext(ctx)
				if span != nil {
					span = tracer.StartSpan("get_correlation_id", opentracing.ChildOf(span.Context()))
					otag.SpanKindRPCClient.Set(span)
					ctx = opentracing.ContextWithSpan(ctx, span)

					// Propagate the opentracing span.
					var carrier = make(opentracing.TextMapCarrier)
					var err = tracer.Inject(span.Context(), opentracing.TextMap, carrier)
					if err != nil {
						httpErrorHandler(context.TODO(), errors.Wrap(err, "could not inject tracer"), w)
						return
					}

					var md = metadata.New(carrier)
					ctx = metadata.NewOutgoingContext(ctx, md)
				}

				var reply, err = flaki.NextID(ctx, flakiRequest())
				if err != nil {
					correlationID = brokenID(componentName, componentID)
					logger.Log("msg", "could not get correlation ID from flaki", "correlation_id", correlationID)
				} else {
					correlationID = string(reply.Id())
				}

				if span != nil {
					span.Finish()
				}
			}

			var ctx = context.WithValue(req.Context(), "correlation_id", correlationID)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

func httpErrorHandler(_ context.Context, err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var reply, _ = json.MarshalIndent(map[string]string{"error": err.Error()}, "", "  ")
	w.Write(reply)
}

// MakeGRPCCorrelationIDMW retrieve the correlation ID from the GRPC context.
// It there is no such ID, it gets a correlation ID from Flaki.
// The Flaki request is traced.
func MakeGRPCCorrelationIDMW(flaki fb.FlakiClient, tracer opentracing.Tracer, logger log.Logger, componentName, componentID string) func(grpc_transport.Handler) grpc_transport.Handler {
	return func(next grpc_transport.Handler) grpc_transport.Handler {
		return &correlationIDMW{
			flaki:         flaki,
			tracer:        tracer,
			logger:        logger,
			componentName: componentName,
			componentID:   componentID,
			next:          next,
		}
	}
}

type correlationIDMW struct {
	flaki         fb.FlakiClient
	tracer        opentracing.Tracer
	logger        log.Logger
	componentName string
	componentID   string
	next          grpc_transport.Handler
}

// ServeGRPC try to extract an existing correlation ID from the GRPC metadata. It it doesn't exists,
// it gets a correlation ID from Flaki.
// The Flaki request is traced.
func (m *correlationIDMW) ServeGRPC(ctx context.Context, req interface{}) (context.Context, interface{}, error) {
	var correlationID string

	// Get correlation ID from GRPC metadata.
	var md, ok = metadata.FromIncomingContext(ctx)
	if ok {
		var val = md.Get("correlation_id")
		if val != nil {
			correlationID = val[0]
		}
	}

	if correlationID == "" {
		var outgoingCtx context.Context
		var span = opentracing.SpanFromContext(ctx)
		if span != nil {
			span = m.tracer.StartSpan("get_correlation_id", opentracing.ChildOf(span.Context()))
			otag.SpanKindRPCClient.Set(span)
			outgoingCtx = opentracing.ContextWithSpan(ctx, span)

			// Propagate the opentracing span.
			var carrier = make(opentracing.TextMapCarrier)
			var err = m.tracer.Inject(span.Context(), opentracing.TextMap, carrier)
			if err != nil {
				outgoingCtx = context.Background()
			}

			var md = metadata.New(carrier)
			outgoingCtx = metadata.NewOutgoingContext(outgoingCtx, md)
		}

		var reply, err = m.flaki.NextID(outgoingCtx, flakiRequest())
		if err != nil {
			correlationID = brokenID(m.componentName, m.componentID)
			m.logger.Log("msg", "could not get correlation ID from flaki", "correlation_id", correlationID)
		} else {
			correlationID = string(reply.Id())
		}

		if span != nil {
			span.Finish()
		}
	}

	ctx = context.WithValue(ctx, "correlation_id", correlationID)
	return m.next.ServeGRPC(ctx, req)
}

// If we cannot get ID from Flaki, we generate a random one with the following
// format: broken-<componentName>-<componentID>-<time>-<random number>
func brokenID(componentName, componentID string) string {
	var id = strconv.FormatUint(rand.Uint64(), 10)
	return fmt.Sprintf("broken-%s-%s-%s-%s", componentName, componentID, time.Now().UTC(), id)
}

func flakiRequest() *flatbuffers.Builder {
	var b = flatbuffers.NewBuilder(0)

	fb.FlakiRequestStart(b)
	b.Finish(fb.FlakiRequestEnd(b))

	return b
}
