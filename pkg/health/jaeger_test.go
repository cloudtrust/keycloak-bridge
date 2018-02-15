package health

import (
	"context"
	"time"
)

// Mock Jaeger module.
type mockJaegerModule struct {
	fail bool
}

func (m *mockJaegerModule) HealthChecks(context.Context) []JaegerHealthReport {
	if m.fail {
		return []JaegerHealthReport{JaegerHealthReport{
			Name:     "jaeger",
			Duration: time.Duration(1 * time.Second).String(),
			Status:   KO,
			Error:    "fail",
		}}
	}
	return []JaegerHealthReport{JaegerHealthReport{
		Name:     "jaeger",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
	}}
}
