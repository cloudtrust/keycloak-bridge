package health

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthChecks(t *testing.T) {
	var mockInflux = &mockInflux{fail: false}

	var m = NewInfluxModule(mockInflux)

	mockInflux.called = false
	var report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockInflux.called)
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, OK, report.Status)
	assert.Zero(t, report.Error)

	// Influx fail.
	mockInflux.fail = true
	mockInflux.called = false
	report = m.HealthChecks(context.Background())[0]
	fmt.Println(report)
	assert.True(t, mockInflux.called)
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, KO, report.Status)
	assert.NotZero(t, report.Error)
}

func TestNoopInfluxHealthChecks(t *testing.T) {
	var mockInflux = &mockInflux{fail: false, s: "NOOP"}

	var m = NewInfluxModule(mockInflux)

	mockInflux.called = false
	var report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockInflux.called)
	assert.Equal(t, "ping", report.Name)
	assert.Equal(t, "N/A", report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)
}

// Mock Influx.
type mockInflux struct {
	called bool
	fail   bool
	s      string
}

func (i *mockInflux) Ping(timeout time.Duration) (time.Duration, string, error) {
	i.called = true
	if i.fail {
		return time.Duration(0), "", fmt.Errorf("fail")
	}
	return time.Duration(1 * time.Second), i.s, nil
}

// Mock Influx module.
type mockInfluxModule struct {
	fail bool
}

func (m *mockInfluxModule) HealthChecks(context.Context) []InfluxHealthReport {
	if m.fail {
		return []InfluxHealthReport{InfluxHealthReport{
			Name:     "influx",
			Duration: time.Duration(1 * time.Second).String(),
			Status:   KO,
			Error:    "fail",
		}}
	}
	return []InfluxHealthReport{InfluxHealthReport{
		Name:     "influx",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
	}}
}
