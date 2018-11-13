package health_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type elasticsearchReport struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
	Error    string `json:"error,omitempty"`
}

func TestElasticsearchDisabled(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var (
		enabled = false
		m       = NewElasticsearchModule(s.Client(), s.URL[7:], enabled)
	)

	var jsonReport, err = m.HealthCheck(context.Background(), "ping")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []elasticsearchReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "elasticsearch", r.Name)
	assert.Equal(t, "Deactivated", r.Status)
	assert.Zero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestElasticsearchPing(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var (
		enabled = true
		m       = NewElasticsearchModule(s.Client(), s.URL[7:], enabled)
	)

	var jsonReport, err = m.HealthCheck(context.Background(), "ping")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []elasticsearchReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "ping", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestElasticsearchAllChecks(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var (
		enabled = true
		m       = NewElasticsearchModule(s.Client(), s.URL[7:], enabled)
	)

	var jsonReport, err = m.HealthCheck(context.Background(), "")
	assert.Nil(t, err)

	// Check that the report is a valid json
	var report = []elasticsearchReport{}
	assert.Nil(t, json.Unmarshal(jsonReport, &report))

	var r = report[0]
	assert.Equal(t, "ping", r.Name)
	assert.Equal(t, "OK", r.Status)
	assert.NotZero(t, r.Duration)
	assert.Zero(t, r.Error)
}

func TestElasticsearchUnkownHealthCheck(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var (
		enabled         = true
		m               = NewElasticsearchModule(s.Client(), s.URL[7:], enabled)
		healthCheckName = "unknown"
	)

	var f = func() {
		m.HealthCheck(context.Background(), healthCheckName)
	}
	assert.Panics(t, f)
}
