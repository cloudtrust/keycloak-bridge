package health

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// SentryModule is the health check module for sentry.
type SentryModule interface {
	HealthChecks(context.Context) []SentryReport
}

type sentryModule struct {
	sentry     Sentry
	httpClient SentryHTTPClient
	enabled    bool
}

// SentryReport is the health report returned by the sentry module.
type SentryReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Sentry is the interface of the sentry client.
type Sentry interface {
	URL() string
}

// SentryHTTPClient is the interface of the http client.
type SentryHTTPClient interface {
	Get(string) (*http.Response, error)
}

// NewSentryModule returns the sentry health module.
func NewSentryModule(sentry Sentry, httpClient SentryHTTPClient, enabled bool) SentryModule {
	return &sentryModule{
		sentry:     sentry,
		httpClient: httpClient,
		enabled:    enabled,
	}
}

// HealthChecks executes all health checks for Sentry.
func (m *sentryModule) HealthChecks(context.Context) []SentryReport {
	var reports = []SentryReport{}
	reports = append(reports, m.sentryPingCheck())
	return reports
}

func (m *sentryModule) sentryPingCheck() SentryReport {
	var healthCheckName = "ping"

	if !m.enabled {
		return SentryReport{
			Name:     healthCheckName,
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	var dsn = m.sentry.URL()

	// Get Sentry health status.
	var now = time.Now()
	var err = pingSentry(dsn, m.httpClient)
	var duration = time.Since(now)

	var error string
	var s Status
	switch {
	case err != nil:
		error = fmt.Sprintf("could not ping sentry: %v", err.Error())
		s = KO
	default:
		s = OK
	}

	return SentryReport{
		Name:     healthCheckName,
		Duration: duration.String(),
		Status:   s,
		Error:    error,
	}
}

func pingSentry(dsn string, httpClient SentryHTTPClient) error {
	// Build sentry health url from sentry dsn. The health url is <sentryURL>/_health
	var url string
	if idx := strings.LastIndex(dsn, "/api/"); idx != -1 {
		url = fmt.Sprintf("%s/_health", dsn[:idx])
	}

	// Query sentry health endpoint.
	var res *http.Response
	{
		var err error
		res, err = httpClient.Get(url)
		if err != nil {
			return err
		}
		if res != nil {
			defer res.Body.Close()
		}
	}

	// Chesk response status.
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("http response status code: %v", res.Status)
	}

	// Chesk response body. The sentry health endpoint returns "ok" when there is no issue.
	var response []byte
	{
		var err error
		response, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
	}

	if strings.Compare(string(response), "ok") == 0 {
		return nil
	}

	return fmt.Errorf("response should be 'ok' but is: %v", string(response))
}
