package event

import (
	"context"
	"net/http"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
	grpc_transport "github.com/go-kit/kit/transport/grpc"
	opentracing "github.com/opentracing/opentracing-go"
	otag "github.com/opentracing/opentracing-go/ext"
	"google.golang.org/grpc/metadata"
)

// MakeHTTPTracingMW try to extract an existing span from the HTTP headers. It it exists, we
// continue the span, if not we create a new one.
func MakeHTTPTracingMW(tracer opentracing.Tracer, operationName string) func(http.Handler) http.Handler {
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
			otag.Component.Set(span, "event-service")
			span.SetTag("transport", "http")
			otag.SpanKindRPCServer.Set(span)

			next.ServeHTTP(w, r.WithContext(opentracing.ContextWithSpan(r.Context(), span)))
		})
	}
}

type grpcTracingMW struct {
	next          grpc_transport.Handler
	tracer        opentracing.Tracer
	operationName string
}

// MakeGRPCTracingMW try to extract an existing span from the HTTP headers. It it exists, we
// continue the span, if not we create a new one.
func MakeGRPCTracingMW(tracer opentracing.Tracer, operationName string) func(grpc_transport.Handler) grpc_transport.Handler {
	return func(next grpc_transport.Handler) grpc_transport.Handler {
		return &grpcTracingMW{
			next:          next,
			tracer:        tracer,
			operationName: operationName,
		}
	}
}

// ServeGRPC try to extract an existing span from the GRPC metadata. It it exists, we
// continue the span, if not we create a new one.
func (m *grpcTracingMW) ServeGRPC(ctx context.Context, request interface{}) (context.Context, interface{}, error) {
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
	otag.Component.Set(span, "event-service")
	span.SetTag("transport", "grpc")
	otag.SpanKindRPCServer.Set(span)

	return m.next.ServeGRPC(opentracing.ContextWithSpan(ctx, span), request)
}

// Tracing middleware at component level.
type muxComponentTracingMW struct {
	tracer opentracing.Tracer
	next   MuxComponent
}

// MakeMuxComponentTracingMW makes a tracing middleware at component level.
func MakeMuxComponentTracingMW(tracer opentracing.Tracer) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &muxComponentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// muxComponentTracingMW implements MuxComponent.
func (m *muxComponentTracingMW) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("mux_component", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.Event(ctx, eventType, obj)
}

// Tracing middleware at component level.
type componentTracingMW struct {
	tracer opentracing.Tracer
	next   Component
}

// MakeComponentTracingMW makes a tracing middleware at component level.
func MakeComponentTracingMW(tracer opentracing.Tracer) func(Component) Component {
	return func(next Component) Component {
		return &componentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// componentTracingMW implements Component.
func (m *componentTracingMW) Event(ctx context.Context, event *fb.Event) (interface{}, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("component_component", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.Event(ctx, event)
}

// Tracing middleware at component level.
type adminComponentTracingMW struct {
	tracer opentracing.Tracer
	next   AdminComponent
}

// MakeAdminComponentTracingMW makes a tracing middleware at component level.
func MakeAdminComponentTracingMW(tracer opentracing.Tracer) func(AdminComponent) AdminComponent {
	return func(next AdminComponent) AdminComponent {
		return &adminComponentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// adminComponentTracingMW implements Component.
func (m *adminComponentTracingMW) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) (interface{}, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("admin_component", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.AdminEvent(ctx, adminEvent)
}

// Tracing middleware at module level.
type consoleModuleTracingMW struct {
	tracer opentracing.Tracer
	next   ConsoleModule
}

// MakeConsoleModuleTracingMW makes a tracing middleware at component level.
func MakeConsoleModuleTracingMW(tracer opentracing.Tracer) func(ConsoleModule) ConsoleModule {
	return func(next ConsoleModule) ConsoleModule {
		return &consoleModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// consoleModuleTracingMW implements ConsoleModule.
func (m *consoleModuleTracingMW) Print(ctx context.Context, mp map[string]string) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("console_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.Print(ctx, mp)
}

// Tracing middleware at module level.
type statisticModuleTracingMW struct {
	tracer opentracing.Tracer
	next   StatisticModule
}

// MakeStatisticModuleTracingMW makes a tracing middleware at component level.
func MakeStatisticModuleTracingMW(tracer opentracing.Tracer) func(StatisticModule) StatisticModule {
	return func(next StatisticModule) StatisticModule {
		return &statisticModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// statisticModuleTracingMW implements StatisticModule.
func (m *statisticModuleTracingMW) Stats(ctx context.Context, mp map[string]string) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("console_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.Stats(ctx, mp)
}
