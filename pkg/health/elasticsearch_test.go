package health

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	mock "github.com/cloudtrust/common-healthcheck/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestESHealthChecks(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var m = NewElasticsearchModule(s.Client(), s.URL[7:], true)

	// HealthChecks
	{
		var report = m.HealthChecks(context.Background())[0]
		assert.Equal(t, "ping", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, common.OK, report.Status)
		assert.Zero(t, report.Error)
	}
}

func TestNoopESHealthChecks(t *testing.T) {
	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	var m = NewElasticsearchModule(s.Client(), s.URL[7:], false)

	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "es", report.Name)
	assert.Zero(t, report.Duration)
	assert.Equal(t, common.Deactivated, report.Status)
	assert.Zero(t, report.Error)
}

func TestESModuleLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)

	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	var module = NewElasticsearchModule(s.Client(), s.URL[7:], false)

	var m = MakeElasticsearchModuleLoggingMW(mockLogger)(module)

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)

	mockLogger.EXPECT().Log("unit", "HealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	m.HealthChecks(ctx)

	// Without correlation ID.
	var f = func() {
		m.HealthChecks(context.Background())
	}
	assert.Panics(t, f)
}

func TestJaegerReportMarshalJSON(t *testing.T) {
	var report = &ESReport{
		Name:     "ES",
		Duration: 1 * time.Second,
		Status:   common.OK,
		Error:    fmt.Errorf("Error"),
	}

	json, err := report.MarshalJSON()

	assert.Nil(t, err)
	assert.Equal(t, "{\"name\":\"ES\",\"duration\":\"1s\",\"status\":\"OK\",\"error\":\"Error\"}", string(json))
}
