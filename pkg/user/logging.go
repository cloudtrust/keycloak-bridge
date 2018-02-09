package user

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
)

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
func (m *componentLoggingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	defer func(begin time.Time) {
		m.logger.Log("unit", "user", "realm", realm, "correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.GetUsers(ctx, realm)
}

// Logging middleware for the user module.
type moduleLoggingMW struct {
	logger log.Logger
	next   Module
}

// MakeModuleLoggingMW makes a logging middleware for the console module.
func MakeModuleLoggingMW(log log.Logger) func(Module) Module {
	return func(next Module) Module {
		return &moduleLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// moduleLoggingMW implements ConsoleModule.
func (m *moduleLoggingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	defer func(begin time.Time) {
		m.logger.Log("unit", "user", "realm", realm, "correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.GetUsers(ctx, realm)
}
