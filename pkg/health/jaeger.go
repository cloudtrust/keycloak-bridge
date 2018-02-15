package health

import (
	"context"
)

type JaegerModule interface {
	HealthChecks(context.Context) []JaegerHealthReport
}

type JaegerHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

type Jaeger interface {
	//Ping(timeout time.Duration) (time.Duration, string, error)
}

type jaegerModule struct {
	jaeger Jaeger
}

// NewJaegerModule returns the jaeger health module.
func NewJaegerModule(jaeger Jaeger) JaegerModule {
	return &jaegerModule{jaeger: jaeger}
}

// HealthChecks executes all health checks for Jaeger.
func (m *jaegerModule) HealthChecks(context.Context) []JaegerHealthReport {
	var reports = []JaegerHealthReport{}
	reports = append(reports, jaegerPingCheck(m.jaeger))
	return reports
}

func jaegerPingCheck(jaeger Jaeger) JaegerHealthReport {
	return JaegerHealthReport{
		Name:     "ping",
		Duration: "N/A",
		Status:   KO,
		Error:    "Not yet implemented",
	}
}
