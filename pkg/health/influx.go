package health

import (
	"context"
	"time"
)

type InfluxModule interface {
	HealthChecks(context.Context) []InfluxHealthReport
}

type InfluxHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

type Influx interface {
	Ping(timeout time.Duration) (time.Duration, string, error)
}

type influxModule struct {
	influx Influx
}

// NewInfluxModule returns the influx health module.
func NewInfluxModule(influx Influx) InfluxModule {
	return &influxModule{influx: influx}
}

// HealthChecks executes all health checks for Influx.
func (m *influxModule) HealthChecks(context.Context) []InfluxHealthReport {
	var reports = []InfluxHealthReport{}
	reports = append(reports, influxPing(m.influx))
	return reports
}

func influxPing(influx Influx) InfluxHealthReport {
	var d, s, err = influx.Ping(time.Duration(5 * time.Second))

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
