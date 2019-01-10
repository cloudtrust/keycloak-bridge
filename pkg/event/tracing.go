package event

//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	opentracing "github.com/opentracing/opentracing-go"
)

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
func (m *muxComponentTracingMW) Event(ctx context.Context, eventType string, obj []byte) error {
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
func (m *componentTracingMW) Event(ctx context.Context, event *fb.Event) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("event_component", opentracing.ChildOf(span.Context()))
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
func (m *adminComponentTracingMW) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("admin_event_component", opentracing.ChildOf(span.Context()))
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
func (m *consoleModuleTracingMW) Print(ctx context.Context, mp map[string]interface{}) error {
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
func (m *statisticModuleTracingMW) Stats(ctx context.Context, mp map[string]interface{}) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("statistic_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.Stats(ctx, mp)
}
