package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	"github.com/pkg/errors"
)

// NewElasticsearchModule returns the elasticsearch health module.
func NewElasticsearchModule(httpClient HTTPClient, hostPort string, enabled bool) *ElasticsearchModule {
	return &ElasticsearchModule{
		httpClient: httpClient,
		hostPort:   hostPort,
		enabled:    enabled,
	}
}

// ElasticsearchModule is the health check module for elasticsearch.
type ElasticsearchModule struct {
	httpClient HTTPClient
	hostPort   string
	enabled    bool
}

// HTTPClient is the interface of the http client client.
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

type elasticsearchReport struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

// HealthCheck executes the desired elasticsearch health check.
func (m *ElasticsearchModule) HealthCheck(_ context.Context, name string) (json.RawMessage, error) {
	if !m.enabled {
		return json.MarshalIndent([]elasticsearchReport{{Name: "elasticsearch", Status: common.Deactivated.String()}}, "", "  ")
	}

	var reports []elasticsearchReport
	switch name {
	case "":
		reports = append(reports, m.elasticsearchPing())
	case "ping":
		reports = append(reports, m.elasticsearchPing())
	default:
		// Should not happen: there is a middleware validating the inputs name.
		panic(fmt.Sprintf("Unknown elasticsearch health check name: %v", name))
	}

	return json.MarshalIndent(reports, "", "  ")
}

func (m *ElasticsearchModule) elasticsearchPing() elasticsearchReport {
	var name = "ping"
	var status = common.OK

	// query elasticsearch health check URL
	var now = time.Now()
	var res, err = m.httpClient.Get(fmt.Sprintf("http://%s", m.hostPort))
	var duration = time.Since(now)

	switch {
	case err != nil:
		err = errors.Wrap(err, "could not query elasticsearch")
		status = common.KO
	case res.StatusCode != http.StatusOK:
		err = errors.Wrapf(err, "elasticsearch returned invalid status code: %v", res.StatusCode)
		status = common.KO
	default:
		status = common.OK
	}

	return elasticsearchReport{
		Name:     name,
		Duration: duration.String(),
		Status:   status.String(),
		Error:    str(err),
	}
}
