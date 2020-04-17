package event

import (
	"context"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/database"
	"github.com/cloudtrust/common-service/tracing"
	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
)

// Tracing middleware at component level.
type muxComponentTracingMW struct {
	tracer tracing.OpentracingClient
	next   MuxComponent
}

// MakeMuxComponentTracingMW makes a tracing middleware at component level.
func MakeMuxComponentTracingMW(tracer tracing.OpentracingClient) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &muxComponentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// muxComponentTracingMW implements MuxComponent.
func (m *muxComponentTracingMW) Event(ctx context.Context, eventType string, obj []byte) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "mux_component", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.Event(ctx, eventType, obj)
}

// Tracing middleware at component level.
type componentTracingMW struct {
	tracer tracing.OpentracingClient
	next   Component
}

// MakeComponentTracingMW makes a tracing middleware at component level.
func MakeComponentTracingMW(tracer tracing.OpentracingClient) func(Component) Component {
	return func(next Component) Component {
		return &componentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// componentTracingMW implements Component.
func (m *componentTracingMW) Event(ctx context.Context, event *fb.Event) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "event_component", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.Event(ctx, event)
}

// Tracing middleware at component level.
type adminComponentTracingMW struct {
	tracer tracing.OpentracingClient
	next   AdminComponent
}

// MakeAdminComponentTracingMW makes a tracing middleware at component level.
func MakeAdminComponentTracingMW(tracer tracing.OpentracingClient) func(AdminComponent) AdminComponent {
	return func(next AdminComponent) AdminComponent {
		return &adminComponentTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// adminComponentTracingMW implements Component.
func (m *adminComponentTracingMW) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "admin_event_component", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.AdminEvent(ctx, adminEvent)
}

// Tracing middleware at module level.
type consoleModuleTracingMW struct {
	tracer tracing.OpentracingClient
	next   ConsoleModule
}

// MakeConsoleModuleTracingMW makes a tracing middleware at component level.
func MakeConsoleModuleTracingMW(tracer tracing.OpentracingClient) func(ConsoleModule) ConsoleModule {
	return func(next ConsoleModule) ConsoleModule {
		return &consoleModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// consoleModuleTracingMW implements ConsoleModule.
func (m *consoleModuleTracingMW) Print(ctx context.Context, mp map[string]string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "console_module", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.Print(ctx, mp)
}

// Tracing middleware at module level.
type statisticModuleTracingMW struct {
	tracer tracing.OpentracingClient
	next   StatisticModule
}

// MakeStatisticModuleTracingMW makes a tracing middleware at component level.
func MakeStatisticModuleTracingMW(tracer tracing.OpentracingClient) func(StatisticModule) StatisticModule {
	return func(next StatisticModule) StatisticModule {
		return &statisticModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// statisticModuleTracingMW implements StatisticModule.
func (m *statisticModuleTracingMW) Stats(ctx context.Context, mp map[string]string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "statistic_module", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.Stats(ctx, mp)
}

// Tracing middleware at module level.
type eventsDBModuleTracingMW struct {
	tracer tracing.OpentracingClient
	next   database.EventsDBModule
}

// MakeEventsDBModuleTracingMW makes a tracing middleware at component level.
func MakeEventsDBModuleTracingMW(tracer tracing.OpentracingClient) func(database.EventsDBModule) database.EventsDBModule {
	return func(next database.EventsDBModule) database.EventsDBModule {
		return &eventsDBModuleTracingMW{
			tracer: tracer,
			next:   next,
		}
	}
}

// statisticModuleTracingMW implements StatisticModule.
func (m *eventsDBModuleTracingMW) Store(ctx context.Context, mp map[string]string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "eventsDB_module", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.Store(ctx, mp)
}

// statisticModuleTracingMW implements StatisticModule.
func (m *eventsDBModuleTracingMW) ReportEvent(ctx context.Context, apiCall string, origin string, values ...string) error {
	var f tracing.Finisher
	ctx, f = m.tracer.TryStartSpanWithTag(ctx, "eventsDB_module", KeyCorrelationID, ctx.Value(cs.CtContextCorrelationID).(string))
	if f != nil {
		defer f.Finish()
	}

	return m.next.ReportEvent(ctx, apiCall, origin, values...)
}
