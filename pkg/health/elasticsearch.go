package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
)

// NewElasticsearchModule returns the elasticsearch health module.
func NewElasticsearchModule(httpClient HTTPClient, hostPort string, enabled bool) *ESModule {
	return &ESModule{
		httpClient: httpClient,
		hostPort:   hostPort,
		enabled:    enabled,
	}
}

// ESModule is the health check module for elasticsearch.
type ESModule struct {
	httpClient HTTPClient
	hostPort   string
	enabled    bool
}

// HTTPClient is the interface of the http client client.
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

// ESReport is the health report returned by the elasticsearch module.
type ESReport struct {
	Name     string
	Duration time.Duration
	Status   common.Status
	Error    error
}

// MarshalJSON marshal the elasticsearch report.
func (r *ESReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Name     string `json:"name"`
		Duration string `json:"duration"`
		Status   string `json:"status"`
		Error    string `json:"error"`
	}{
		Name:     r.Name,
		Duration: r.Duration.String(),
		Status:   r.Status.String(),
		Error:    err(r.Error),
	})
}

// HealthChecks executes all health checks for elasticsearch.
func (m *ESModule) HealthChecks(context.Context) []ESReport {
	if !m.enabled {
		return []ESReport{{Name: "es", Status: common.Deactivated}}
	}

	var reports = []ESReport{}
	reports = append(reports, m.elasticsearchPing())
	return reports
}

func (m *ESModule) elasticsearchPing() ESReport {
	var healthCheckName = "ping"

	// query jaeger collector health check URL
	var now = time.Now()
	var res, err = m.httpClient.Get(fmt.Sprintf("http://%s", m.hostPort))
	var duration = time.Since(now)

	var hcErr error
	var s common.Status
	switch {
	case err != nil:
		hcErr = errors.Wrap(err, "could not query elasticsearch")
		s = common.KO
	case res.StatusCode != http.StatusOK:
		hcErr = errors.Wrapf(err, "elasticsearch returned invalid status code: %v", res.StatusCode)
		s = common.KO
	default:
		s = common.OK
	}

	return ESReport{
		Name:     healthCheckName,
		Duration: duration,
		Status:   s,
		Error:    hcErr,
	}
}

// MakeElasticsearchModuleLoggingMW makes a logging middleware at module level.
func MakeElasticsearchModuleLoggingMW(logger log.Logger) func(ESHealthChecker) ESHealthChecker {
	return func(next ESHealthChecker) ESHealthChecker {
		return &elasticsearchModuleLoggingMW{
			logger: logger,
			next:   next,
		}
	}
}

// Logging middleware at module level.
type elasticsearchModuleLoggingMW struct {
	logger log.Logger
	next   ESHealthChecker
}

// elasticsearchModuleLoggingMW implements ElasticsearchHealthChecker. There must be a key "correlation_id" with a string value in the context.
func (m *elasticsearchModuleLoggingMW) HealthChecks(ctx context.Context) []ESReport {
	defer func(begin time.Time) {
		m.logger.Log("unit", "HealthChecks", "correlation_id", ctx.Value("correlation_id").(string), "took", time.Since(begin))
	}(time.Now())

	return m.next.HealthChecks(ctx)
}
