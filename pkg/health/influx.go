package health

//go:generate mockgen -destination=./mock/influx.go -package=mock -mock_names=InfluxModule=InfluxModule,Influx=Influx github.com/cloudtrust/keycloak-bridge/pkg/health InfluxModule,Influx

import (
	"context"
	"time"
)

// InfluxModule is the health check module for influx.
type InfluxModule interface {
	HealthChecks(context.Context) []InfluxHealthReport
}

type influxModule struct {
	influx Influx
}

// InfluxHealthReport is the health report returned by the influx module.
type InfluxHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Influx is the interface of the influx client.
type Influx interface {
	Ping(timeout time.Duration) (time.Duration, string, error)
}

// NewInfluxModule returns the influx health module.
func NewInfluxModule(influx Influx) InfluxModule {
	return &influxModule{influx: influx}
}

// HealthChecks executes all health checks for influx.
func (m *influxModule) HealthChecks(context.Context) []InfluxHealthReport {
	var reports = []InfluxHealthReport{}
	reports = append(reports, influxPing(m.influx))
	return reports
}

func influxPing(influx Influx) InfluxHealthReport {
	var d, s, err = influx.Ping(5 * time.Second)

	// If influx is deactivated.
	if s == "NOOP" {
		return InfluxHealthReport{
			Name:     "ping",
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	var status = OK
	var error = ""
	if err != nil {
		status = KO
		error = err.Error()
	}

	return InfluxHealthReport{
		Name:     "ping",
		Duration: d.String(),
		Status:   status,
		Error:    error,
	}
}
