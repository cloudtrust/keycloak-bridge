package event

//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram

import (
	"context"
	"time"

	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/go-kit/kit/metrics"
)

// Instrumenting middleware for the mux component.
type muxComponentInstrumentingMW struct {
	h    metrics.Histogram
	next MuxComponent
}

// MakeMuxComponentInstrumentingMW makes an instrumenting middleware for the mux component.
func MakeMuxComponentInstrumentingMW(h metrics.Histogram) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &muxComponentInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// muxComponentInstrumentingMW implements MuxComponent.
func (m *muxComponentInstrumentingMW) Event(ctx context.Context, eventType string, obj []byte) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.Event(ctx, eventType, obj)
}

// Instrumenting middleware for the event component.
type componentInstrumentingMW struct {
	h    metrics.Histogram
	next Component
}

// MakeComponentInstrumentingMW makes an instrumenting middleware for the event component.
func MakeComponentInstrumentingMW(h metrics.Histogram) func(Component) Component {
	return func(next Component) Component {
		return &componentInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// componentInstrumentingMW implements Component.
func (m *componentInstrumentingMW) Event(ctx context.Context, event *fb.Event) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.Event(ctx, event)
}

// Instrumenting middleware for the admin event component.
type adminComponentInstrumentingMW struct {
	h    metrics.Histogram
	next AdminComponent
}

// MakeAdminComponentInstrumentingMW makes a Instrumenting middleware for the admin event component.
func MakeAdminComponentInstrumentingMW(h metrics.Histogram) func(AdminComponent) AdminComponent {
	return func(next AdminComponent) AdminComponent {
		return &adminComponentInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// adminComponentInstrumentingMW implements AdminComponent.
func (m *adminComponentInstrumentingMW) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.AdminEvent(ctx, adminEvent)
}

// Instrumenting middleware at module level.
type consoleModuleInstrumentingMW struct {
	h    metrics.Histogram
	next ConsoleModule
}

// MakeConsoleModuleInstrumentingMW makes an instrumenting middleware at module level.
func MakeConsoleModuleInstrumentingMW(h metrics.Histogram) func(ConsoleModule) ConsoleModule {
	return func(next ConsoleModule) ConsoleModule {
		return &consoleModuleInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// consoleModuleInstrumentingMW implements Module.
func (m *consoleModuleInstrumentingMW) Print(ctx context.Context, mp map[string]string) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.Print(ctx, mp)
}

// Instrumenting middleware at module level.
type statisticModuleInstrumentingMW struct {
	h    metrics.Histogram
	next StatisticModule
}

// MakeStatisticModuleInstrumentingMW makes an instrumenting middleware at module level.
func MakeStatisticModuleInstrumentingMW(h metrics.Histogram) func(StatisticModule) StatisticModule {
	return func(next StatisticModule) StatisticModule {
		return &statisticModuleInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// consoleModuleInstrumentingMW implements Module.
func (m *statisticModuleInstrumentingMW) Stats(ctx context.Context, mp map[string]string) error {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.Stats(ctx, mp)
}
