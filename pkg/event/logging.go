package event

import (
	"context"
	"time"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/keycloak-bridge/api/event/fb"
	"github.com/go-kit/kit/log"
)

// Logging middleware for the mux component.
type muxComponentLoggingMW struct {
	logger log.Logger
	next   MuxComponent
}

// MakeMuxComponentLoggingMW makes a logging middleware for the mux component.
func MakeMuxComponentLoggingMW(log log.Logger) func(MuxComponent) MuxComponent {
	return func(next MuxComponent) MuxComponent {
		return &muxComponentLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// muxComponentLoggingMW implements MuxComponent.
func (m *muxComponentLoggingMW) Event(ctx context.Context, eventType string, obj []byte) error {
	defer func(begin time.Time) {
		m.logger.Log("unit", "Event", "type", eventType, "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.Event(ctx, eventType, obj)
}

// Logging middleware for the event component.
type componentLoggingMW struct {
	logger log.Logger
	next   Component
}

// MakeComponentLoggingMW makes a logging middleware for the event component.
func MakeComponentLoggingMW(log log.Logger) func(Component) Component {
	return func(next Component) Component {
		return &componentLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// componentLoggingMW implements Component.
func (m *componentLoggingMW) Event(ctx context.Context, event *fb.Event) error {
	defer func(begin time.Time) {
		m.logger.Log("unit", "Event", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.Event(ctx, event)
}

// Logging middleware for the admin event component.
type adminComponentLoggingMW struct {
	logger log.Logger
	next   AdminComponent
}

// MakeAdminComponentLoggingMW makes a logging middleware for the admin event component.
func MakeAdminComponentLoggingMW(log log.Logger) func(AdminComponent) AdminComponent {
	return func(next AdminComponent) AdminComponent {
		return &adminComponentLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// adminComponentLoggingMW implements AdminComponent.
func (m *adminComponentLoggingMW) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) error {
	defer func(begin time.Time) {
		m.logger.Log("unit", "AdminEvent", "correlation_id", ctx.Value(cs.CtContextCorrelationID).(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.AdminEvent(ctx, adminEvent)
}

// Logging middleware for the console module.
type consoleModuleLoggingMW struct {
	logger log.Logger
	next   ConsoleModule
}

// MakeConsoleModuleLoggingMW makes a logging middleware for the console module.
func MakeConsoleModuleLoggingMW(log log.Logger) func(ConsoleModule) ConsoleModule {
	return func(next ConsoleModule) ConsoleModule {
		return &consoleModuleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// consoleModuleLoggingMW implements ConsoleModule.
func (m *consoleModuleLoggingMW) Print(ctx context.Context, mp map[string]string) error {
	defer func(begin time.Time) {
		m.logger.Log("method", "Print", "args", mp, "took", time.Since(begin))
	}(time.Now())
	return m.next.Print(ctx, mp)
}

// Logging middleware for the statistic module.
type statisticModuleLoggingMW struct {
	logger log.Logger
	next   StatisticModule
}

// MakeStatisticModuleLoggingMW makes a logging middleware for the statistic module.
func MakeStatisticModuleLoggingMW(log log.Logger) func(StatisticModule) StatisticModule {
	return func(next StatisticModule) StatisticModule {
		return &statisticModuleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// statisticModuleLoggingMW implements StatisticModule.
func (m *statisticModuleLoggingMW) Stats(ctx context.Context, mp map[string]string) error {
	defer func(begin time.Time) {
		m.logger.Log("method", "Stats", "args", mp, "took", time.Since(begin))
	}(time.Now())
	return m.next.Stats(ctx, mp)
}

// Logging middleware for the statistic module.
type eventsDBModuleLoggingMW struct {
	logger log.Logger
	next   EventsDBModule
}

// MakeStatisticModuleLoggingMW makes a logging middleware for the statistic module.
func MakeEventsDBModuleLoggingMW(log log.Logger) func(EventsDBModule) EventsDBModule {
	return func(next EventsDBModule) EventsDBModule {
		return &eventsDBModuleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// statisticModuleLoggingMW implements StatisticModule.
func (m *eventsDBModuleLoggingMW) Store(ctx context.Context, mp map[string]string) error {
	defer func(begin time.Time) {
		m.logger.Log("method", "Store", "args", mp, "took", time.Since(begin))
	}(time.Now())
	return m.next.Store(ctx, mp)
}
