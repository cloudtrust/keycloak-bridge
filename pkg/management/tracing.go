package management

//go:generate mockgen -destination=./mock/tracing.go -package=mock -mock_names=Tracer=Tracer,Span=Span,SpanContext=SpanContext github.com/opentracing/opentracing-go Tracer,Span,SpanContext

import (
	"context"

	opentracing "github.com/opentracing/opentracing-go"
)

// Tracing middleware at module level.
type configDBModuleTracingMW struct {
	tracer opentracing.Tracer
	next   ConfigurationDBModule
}

// MakeConfigurationDBModuleTracingMW makes a tracing middleware at component level.
func MakeConfigurationDBModuleTracingMW(tracer opentracing.Tracer) func(ConfigurationDBModule) ConfigurationDBModule {
	return func(next ConfigurationDBModule) ConfigurationDBModule {
		return &configDBModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) StoreOrUpdate(ctx context.Context, realmName string, configJSON string) error {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("configurationDB_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.StoreOrUpdate(ctx, realmName, configJSON)
}

// configDBModuleTracingMW implements StatisticModule.
func (m *configDBModuleTracingMW) GetConfiguration(ctx context.Context, realmName string) (string, error) {
	if span := opentracing.SpanFromContext(ctx); span != nil {
		span = m.tracer.StartSpan("configurationDB_module", opentracing.ChildOf(span.Context()))
		defer span.Finish()
		span.SetTag("correlation_id", ctx.Value("correlation_id").(string))

		ctx = opentracing.ContextWithSpan(ctx, span)
	}

	return m.next.GetConfiguration(ctx, realmName)
}
