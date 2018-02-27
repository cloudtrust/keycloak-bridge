package user

//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext

import (
	"context"

	opentracing "github.com/opentracing/opentracing-go"
)

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
func (m *componentTracingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("user_component", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.GetUsers(ctx, realm)
}

// Tracing middleware at module level.
type moduleTracingMW struct {
	tracer opentracing.Tracer
	next   Module
}

// MakeModuleTracingMW makes a tracing middleware at component level.
func MakeModuleTracingMW(tracer opentracing.Tracer) func(Module) Module {
	return func(next Module) Module {
		return &moduleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// moduleTracingMW implements Module.
func (m *moduleTracingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("user_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.GetUsers(ctx, realm)
}
