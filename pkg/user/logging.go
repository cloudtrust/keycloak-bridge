package user

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
)

// Logging middleware at component level.
type componentLoggingMW struct {
	logger log.Logger
	next   KeycloakComponent
}

// MakeComponentLoggingMW makes a logging middleware at component level.
func MakeComponentLoggingMW(log log.Logger) func(KeycloakComponent) KeycloakComponent {
	return func(next KeycloakComponent) KeycloakComponent {
		return &componentLoggingMW{
			logger: log,
			next:   next,
		}
	}
}

// componentLoggingMW implements Component.
func (m *componentLoggingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	defer func(begin time.Time) {
		m.logger.Log("unit", "GetUsers", "realm", realm, "correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
	}(time.Now())
	return m.next.GetUsers(ctx, realm)
}
