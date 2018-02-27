package health

//go:generate mockgen -destination=./mock/jaeger.go -package=mock -mock_names=JaegerModule=JaegerModule,Jaeger=Jaeger github.com/cloudtrust/keycloak-bridge/pkg/health JaegerModule,Jaeger

import (
	"context"
)

// JaegerModule is the health check module for jaeger.
type JaegerModule interface {
	HealthChecks(context.Context) []JaegerHealthReport
}

type jaegerModule struct {
	jaeger Jaeger
}

// JaegerHealthReport is the health report returned by the jaeger module.
type JaegerHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Jaeger is the interface of the jaeger client.
type Jaeger interface {
	//Ping(timeout time.Duration) (time.Duration, error)
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
