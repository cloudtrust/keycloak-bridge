package health

import (
	"context"
)

// Status is the status of the health check.
type Status int

const (
	// OK is the status for a successful health check.
	OK Status = iota
	// KO is the status for an unsuccessful health check.
	KO
	// Degraded is the status for a degraded service, e.g. the service still works, but the metrics DB is KO.
	Degraded
	// Deactivated is the status for a service that is deactivated, e.g. we can disable error tracking, instrumenting, tracing,...
	Deactivated
)

func (s Status) String() string {
	var names = []string{"OK", "KO", "Degraded", "Deactivated"}

	if s < OK || s > Deactivated {
		return "Unknown"
	}

	return names[s]
}

// Component is the health component interface.
type Component interface {
	InfluxHealthChecks(context.Context) Reports
	JaegerHealthChecks(context.Context) Reports
	RedisHealthChecks(context.Context) Reports
	SentryHealthChecks(context.Context) Reports
	KeycloakHealthChecks(context.Context) Reports
	AllHealthChecks(context.Context) map[string]string
}

// Reports contains the results of all health tests for a given module.
type Reports struct {
	Reports []Report
}

// Report contains the result of one health test.
type Report struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// component is the Health component.
type component struct {
	influx   InfluxModule
	jaeger   JaegerModule
	redis    RedisModule
	sentry   SentryModule
	keycloak KeycloakModule
}

// NewComponent returns the health component.
func NewComponent(influx InfluxModule, jaeger JaegerModule, redis RedisModule, sentry SentryModule, keycloak KeycloakModule) Component {
	return &component{
		influx:   influx,
		jaeger:   jaeger,
		redis:    redis,
		sentry:   sentry,
		keycloak: keycloak,
	}
}

// InfluxHealthChecks uses the health component to test the Influx health.
func (c *component) InfluxHealthChecks(ctx context.Context) Reports {
	var reports = c.influx.HealthChecks(ctx)
	var hr = Reports{}
	for _, r := range reports {
		hr.Reports = append(hr.Reports, Report(r))
	}
	return hr
}

// JaegerHealthChecks uses the health component to test the Jaeger health.
func (c *component) JaegerHealthChecks(ctx context.Context) Reports {
	var reports = c.jaeger.HealthChecks(ctx)
	var hr = Reports{}
	for _, r := range reports {
		hr.Reports = append(hr.Reports, Report(r))
	}
	return hr
}

// RedisHealthChecks uses the health component to test the Redis health.
func (c *component) RedisHealthChecks(ctx context.Context) Reports {
	var reports = c.redis.HealthChecks(ctx)
	var hr = Reports{}
	for _, r := range reports {
		hr.Reports = append(hr.Reports, Report(r))
	}
	return hr
}

// SentryHealthChecks uses the health component to test the Sentry health.
func (c *component) SentryHealthChecks(ctx context.Context) Reports {
	var reports = c.sentry.HealthChecks(ctx)
	var hr = Reports{}
	for _, r := range reports {
		hr.Reports = append(hr.Reports, Report(r))
	}
	return hr
}

// KeycloakHealthChecks uses the health component to test the Keycloak health.
func (c *component) KeycloakHealthChecks(ctx context.Context) Reports {
	var reports = c.keycloak.HealthChecks(ctx)
	var hr = Reports{}
	for _, r := range reports {
		hr.Reports = append(hr.Reports, Report(r))
	}
	return hr
}

// AllChecks call all component checks and build a general health report.
func (c *component) AllHealthChecks(ctx context.Context) map[string]string {
	var reports = map[string]string{}

	reports["influx"] = determineStatus(c.InfluxHealthChecks(ctx))
	reports["jaeger"] = determineStatus(c.JaegerHealthChecks(ctx))
	reports["keycloak"] = determineStatus(c.KeycloakHealthChecks(ctx))
	reports["redis"] = determineStatus(c.RedisHealthChecks(ctx))
	reports["sentry"] = determineStatus(c.SentryHealthChecks(ctx))

	return reports
}

// determineStatus parse all the tests reports and output a global status.
func determineStatus(reports Reports) string {
	var degraded = false
	for _, r := range reports.Reports {
		switch r.Status {
		case Deactivated:
			// If the status is Deactivated, we do not need to go through all tests reports, all
			// status will be the same.
			return Deactivated.String()
		case KO:
			return KO.String()
		case Degraded:
			degraded = true
		}
	}
	if degraded {
		return Degraded.String()
	}
	return OK.String()
}
