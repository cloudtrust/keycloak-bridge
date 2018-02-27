package health

//go:generate mockgen -destination=./mock/sentry.go -package=mock -mock_names=SentryModule=SentryModule,Sentry=Sentry github.com/cloudtrust/keycloak-bridge/pkg/health SentryModule,Sentry

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
	HealthChecks(context.Context) []SentryHealthReport
}

type sentryModule struct {
	sentry     Sentry
	httpClient HTTPClient
}

// SentryHealthReport is the health report returned by the sentry module.
type SentryHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Sentry is the interface of the sentry client.
type Sentry interface {
	URL() string
}

// HTTPClient is the interface of the http client.
type HTTPClient interface {
	Get(string) (*http.Response, error)
}

// NewSentryModule returns the sentry health module.
func NewSentryModule(sentry Sentry, httpClient HTTPClient) SentryModule {
	return &sentryModule{
		sentry:     sentry,
		httpClient: httpClient,
	}
}

// HealthChecks executes all health checks for Sentry.
func (m *sentryModule) HealthChecks(context.Context) []SentryHealthReport {
	var reports = []SentryHealthReport{}
	reports = append(reports, sentryPingCheck(m.sentry, m.httpClient))
	return reports
}

func sentryPingCheck(sentry Sentry, httpClient HTTPClient) SentryHealthReport {
	var dsn = sentry.URL()

	// If sentry is deactivated.
	if dsn == "" {
		return SentryHealthReport{
			Name:     "ping",
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	// Get Sentry health status.
	var now = time.Now()
	var status, err = getSentryStatus(dsn, httpClient)
	var duration = time.Since(now)

	var error = ""
	if err != nil {
		error = err.Error()
	}

	return SentryHealthReport{
		Name:     "ping",
		Duration: duration.String(),
		Status:   status,
		Error:    error,
	}
}

func getSentryStatus(dsn string, httpClient HTTPClient) (Status, error) {

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
			return KO, err
		}
		if res != nil {
			defer res.Body.Close()
		}
	}

	// Chesk response status.
	if res.StatusCode != http.StatusOK {
		return KO, fmt.Errorf("http response status code: %v", res.Status)
	}

	// Chesk response body. The sentry health endpoint returns "ok" when there is no issue.
	var response []byte
	{
		var err error
		response, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return KO, err
		}
	}

	if strings.Compare(string(response), "ok") == 0 {
		return OK, nil
	}

	return KO, fmt.Errorf("response should be 'ok' but is: %v", string(response))
}
