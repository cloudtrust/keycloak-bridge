package main

//go:generate mockgen -source=instrumenting.go -destination=./mock/instrumenting.go -package=mock -mock_names=Influx=Influx,GoKitMetrics=GoKitMetrics github.com/cloudtrust/keycloak-bridge/cmd Influx,GoKitMetrics

import (
	"time"

	"github.com/go-kit/kit/metrics"
	metric "github.com/go-kit/kit/metrics/influx"
	influx "github.com/influxdata/influxdb/client/v2"
)

// Influx is the Influx client interface.
type Influx interface {
	Ping(timeout time.Duration) (time.Duration, string, error)
	Write(bp influx.BatchPoints) error
	Close() error
}

// GoKitMetrics is the interface of the go-kit metrics.
type GoKitMetrics interface {
	NewCounter(name string) *metric.Counter
	NewGauge(name string) *metric.Gauge
	NewHistogram(name string) *metric.Histogram
	WriteLoop(c <-chan time.Time, w metric.BatchPointsWriter)
}

// InfluxMetrics sends metrics to the Influx DB.
type InfluxMetrics struct {
	influx  Influx
	metrics GoKitMetrics
}

// NewMetrics returns an InfluxMetrics.
func NewMetrics(influx Influx, metrics GoKitMetrics) *InfluxMetrics {
	return &InfluxMetrics{
		influx:  influx,
		metrics: metrics,
	}
}

// NewCounter returns a go-kit Counter.
func (m *InfluxMetrics) NewCounter(name string) metrics.Counter {
	return m.metrics.NewCounter(name)
}

// NewGauge returns a go-kit Gauge.
func (m *InfluxMetrics) NewGauge(name string) metrics.Gauge {
	return m.metrics.NewGauge(name)
}

// NewHistogram returns a go-kit Histogram.
func (m *InfluxMetrics) NewHistogram(name string) metrics.Histogram {
	return m.metrics.NewHistogram(name)
}

// Write writes the data to the Influx DB.
func (m *InfluxMetrics) Write(bp influx.BatchPoints) error {
	return m.influx.Write(bp)
}

// WriteLoop writes the data to the Influx DB.
func (m *InfluxMetrics) WriteLoop(c <-chan time.Time) {
	m.metrics.WriteLoop(c, m.influx)
}

// Ping test the connection to the Influx DB.
func (m *InfluxMetrics) Ping(timeout time.Duration) (time.Duration, string, error) {
	return m.influx.Ping(timeout)
}

// NoopMetrics is an Influx metrics that does nothing.
type NoopMetrics struct{}

// NewCounter returns a Counter that does nothing.
func (m *NoopMetrics) NewCounter(name string) metrics.Counter { return &NoopCounter{} }

// NewGauge returns a Gauge that does nothing.
func (m *NoopMetrics) NewGauge(name string) metrics.Gauge { return &NoopGauge{} }

// NewHistogram returns an Histogram that does nothing.
func (m *NoopMetrics) NewHistogram(name string) metrics.Histogram { return &NoopHistogram{} }

// Write does nothing.
func (m *NoopMetrics) Write(bp influx.BatchPoints) error { return nil }

// WriteLoop does nothing.
func (m *NoopMetrics) WriteLoop(c <-chan time.Time) {}

// Ping does nothing.
func (m *NoopMetrics) Ping(timeout time.Duration) (time.Duration, string, error) {
	return time.Duration(0), "", nil
}

// NoopCounter is a Counter that does nothing.
type NoopCounter struct{}

// With does nothing.
func (c *NoopCounter) With(labelValues ...string) metrics.Counter { return c }

// Add does nothing.
func (c *NoopCounter) Add(delta float64) {}

// NoopGauge is a Gauge that does nothing.
type NoopGauge struct{}

// With does nothing.
func (g *NoopGauge) With(labelValues ...string) metrics.Gauge { return g }

// Set does nothing.
func (g *NoopGauge) Set(value float64) {}

// Add does nothing.
func (g *NoopGauge) Add(delta float64) {}

// NoopHistogram is an Histogram that does nothing.
type NoopHistogram struct{}

// With does nothing.
func (h *NoopHistogram) With(labelValues ...string) metrics.Histogram { return h }

// Observe does nothing.
func (h *NoopHistogram) Observe(value float64) {}
