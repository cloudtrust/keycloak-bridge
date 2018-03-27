package health

//go:generate mockgen -destination=./mock/jaeger.go -package=mock -mock_names=JaegerModule=JaegerModule,SystemDConn=SystemDConn  github.com/cloudtrust/keycloak-bridge/pkg/health JaegerModule,SystemDConn

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-systemd/dbus"
)

const (
	agentSystemDUnitName = "agent.service"
)

// JaegerModule is the health check module for jaeger.
type JaegerModule interface {
	HealthChecks(context.Context) []JaegerReport
}

type jaegerModule struct {
	conn                    SystemDConn
	collectorHealthCheckURL string
	httpClient              JaegerHTTPClient
	enabled                 bool
}

// JaegerReport is the health report returned by the jaeger module.
type JaegerReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// SystemDConn is interface of systemd D-Bus connection.
type SystemDConn interface {
	ListUnitsByNames(units []string) ([]dbus.UnitStatus, error)
}

// JaegerHTTPClient is the interface of the http client.
type JaegerHTTPClient interface {
	Get(string) (*http.Response, error)
}

// NewJaegerModule returns the jaeger health module.
func NewJaegerModule(conn SystemDConn, httpClient JaegerHTTPClient, collectorHealthCheckURL string, enabled bool) JaegerModule {
	return &jaegerModule{
		conn:                    conn,
		httpClient:              httpClient,
		collectorHealthCheckURL: collectorHealthCheckURL,
		enabled:                 enabled,
	}
}

// HealthChecks executes all health checks for Jaeger.
func (m *jaegerModule) HealthChecks(context.Context) []JaegerReport {
	var reports = []JaegerReport{}
	reports = append(reports, m.jaegerSystemDCheck())
	reports = append(reports, m.jaegerCollectorPing())
	return reports
}

func (m *jaegerModule) jaegerSystemDCheck() JaegerReport {
	var healthCheckName = "jaeger agent systemd unit check"

	if !m.enabled {
		return JaegerReport{
			Name:     healthCheckName,
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	var now = time.Now()
	var units, err = m.conn.ListUnitsByNames([]string{agentSystemDUnitName})
	var duration = time.Since(now)

	var error string
	var s Status
	switch {
	case err != nil:
		error = fmt.Sprintf("could not list systemd unit for name '%s': %v", agentSystemDUnitName, err.Error())
		s = KO
	case len(units) == 0:
		error = fmt.Sprintf("systemd unit '%s' not found: %v", agentSystemDUnitName, err.Error())
		s = KO
	case units[0].ActiveState != "active":
		error = fmt.Sprintf("systemd unit '%s' is not active", agentSystemDUnitName)
		s = KO
	default:
		s = OK
	}

	return JaegerReport{
		Name:     healthCheckName,
		Duration: duration.String(),
		Status:   s,
		Error:    error,
	}
}

func (m *jaegerModule) jaegerCollectorPing() JaegerReport {
	var healthCheckName = "ping jaeger collector"

	if !m.enabled {
		return JaegerReport{
			Name:     healthCheckName,
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	// query jaeger collector health check URL
	var now = time.Now()
	var res, err = m.httpClient.Get("http://" + m.collectorHealthCheckURL)
	var duration = time.Since(now)

	var error string
	var s Status
	switch {
	case err != nil:
		error = fmt.Sprintf("could not query jaeger collector health check service: %v", err.Error())
		s = KO
	case res.StatusCode != 204:
		error = fmt.Sprintf("jaeger health check service returned invalid status code: %v", res.StatusCode)
		s = KO
	default:
		s = OK
	}

	return JaegerReport{
		Name:     healthCheckName,
		Duration: duration.String(),
		Status:   s,
		Error:    error,
	}
}
