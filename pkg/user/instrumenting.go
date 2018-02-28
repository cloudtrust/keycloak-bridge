package user

//go:generate mockgen -destination=./mock/instrumenting.go -package=mock -mock_names=Histogram=Histogram github.com/go-kit/kit/metrics Histogram

import (
	"context"
	"time"

	"github.com/cloudtrust/keycloak-bridge/pkg/user/flatbuffer/fb"
	"github.com/go-kit/kit/metrics"
)

// Instrumenting middleware for the user component.
type componentInstrumentingMW struct {
	h    metrics.Histogram
	next Component
}

// MakeComponentInstrumentingMW makes an instrumenting middleware for the user component.
func MakeComponentInstrumentingMW(h metrics.Histogram) func(Component) Component {
	return func(next Component) Component {
		return &componentInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// componentInstrumentingMW implements Component.
func (m *componentInstrumentingMW) GetUsers(ctx context.Context, req *fb.GetUsersRequest) (*fb.GetUsersResponse, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetUsers(ctx, req)
}

// Instrumenting middleware at module level.
type moduleInstrumentingMW struct {
	h    metrics.Histogram
	next Module
}

// MakeModuleInstrumentingMW makes an instrumenting middleware (at module level).
func MakeModuleInstrumentingMW(h metrics.Histogram) func(Module) Module {
	return func(next Module) Module {
		return &moduleInstrumentingMW{
			h:    h,
			next: next,
		}
	}
}

// moduleInstrumentingMW implements Module.
func (m *moduleInstrumentingMW) GetUsers(ctx context.Context, realm string) ([]string, error) {
	defer func(begin time.Time) {
		m.h.With("correlation_id", ctx.Value("correlation_id").(string)).Observe(time.Since(begin).Seconds())
	}(time.Now())
	return m.next.GetUsers(ctx, realm)
}
