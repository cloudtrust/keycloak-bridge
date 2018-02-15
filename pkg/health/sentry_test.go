package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSentryHealthChecks(t *testing.T) {
	var mockSentry = &mockSentry{url: "https://a:b@sentry.io/api/1/store/"}

	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer s.Close()

	var m = NewSentryModule(mockSentry, s.Client())

	mockSentry.called = false
	var report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockSentry.called)
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, OK, report.Status)
	assert.Zero(t, report.Error)
}

func TestNoopSentryHealthChecks(t *testing.T) {
	var mockSentry = &mockSentry{url: ""}

	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer s.Close()

	var m = NewSentryModule(mockSentry, s.Client())

	mockSentry.called = false
	var report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockSentry.called)
	assert.Equal(t, "ping", report.Name)
	assert.Equal(t, "N/A", report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)
}

// Mock Sentry.
type mockSentry struct {
	url    string
	called bool
}

func (s *mockSentry) URL() string {
	s.called = true
	return s.url
}

// Mock Sentry module.
type mockSentryModule struct {
	fail bool
}

func (m *mockSentryModule) HealthChecks(context.Context) []SentryHealthReport {
	if m.fail {
		return []SentryHealthReport{SentryHealthReport{
			Name:     "sentry",
			Duration: time.Duration(1 * time.Second).String(),
			Status:   KO,
			Error:    "fail",
		}}
	}
	return []SentryHealthReport{SentryHealthReport{
		Name:     "sentry",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
	}}
}
