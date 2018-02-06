package main

import (
	"time"

	"github.com/go-kit/kit/metrics"
	gokit_influx "github.com/go-kit/kit/metrics/influx"
	influx "github.com/influxdata/influxdb/client/v2"
)

// InfluxMetrics sends metrics to the Influx DB.
type InfluxMetrics struct {
	client influx.Client
	gokit  *gokit_influx.Influx
}

// NewMetrics returns an InfluxMetrics.
func NewMetrics(client influx.Client, gokit *gokit_influx.Influx) *InfluxMetrics {
	return &InfluxMetrics{
		client: client,
		gokit:  gokit,
	}
}

// NewCounter returns a go-kit Counter.
func (m *InfluxMetrics) NewCounter(name string) metrics.Counter {
	return m.gokit.NewCounter(name)
}

// NewGauge returns a go-kit Gauge.
func (m *InfluxMetrics) NewGauge(name string) metrics.Gauge {
	return m.gokit.NewGauge(name)
}

// NewHistogram returns a go-kit Histogram.
func (m *InfluxMetrics) NewHistogram(name string) metrics.Histogram {
	return m.gokit.NewHistogram(name)
}

// WriteLoop writes the data to the Influx DB.
func (m *InfluxMetrics) WriteLoop(c <-chan time.Time) {
	m.gokit.WriteLoop(c, m.client)
}

// WriteLoop writes the data to the Influx DB.
func (m *InfluxMetrics) Write(bp influx.BatchPoints) error {
	return m.client.Write(bp)
}

func (m *InfluxMetrics) Ping(timeout time.Duration) (time.Duration, string, error) {
	return m.client.Ping(timeout)
}

// NoopMetrics is an Influx metrics that does nothing.
type NoopMetrics struct{}

func (m *NoopMetrics) NewCounter(name string) metrics.Counter     { return &NoopCounter{} }
func (m *NoopMetrics) NewGauge(name string) metrics.Gauge         { return &NoopGauge{} }
func (m *NoopMetrics) NewHistogram(name string) metrics.Histogram { return &NoopHistogram{} }
func (m *NoopMetrics) WriteLoop(c <-chan time.Time)               {}
func (m *NoopMetrics) Write(bp influx.BatchPoints) error          { return nil }
func (m *NoopMetrics) Ping(timeout time.Duration) (time.Duration, string, error) {
	return time.Duration(0), "Noop", nil
}

// NoopCounter is a Counter that does nothing.
type NoopCounter struct{}

func (c *NoopCounter) With(labelValues ...string) metrics.Counter { return c }
func (c *NoopCounter) Add(delta float64)                          {}

// NoopGauge is a Gauge that does nothing.
type NoopGauge struct{}

func (g *NoopGauge) With(labelValues ...string) metrics.Gauge { return g }
func (g *NoopGauge) Set(value float64)                        {}
func (g *NoopGauge) Add(delta float64)                        {}

// NoopHistogram is an Histogram that does nothing.
type NoopHistogram struct{}

func (h *NoopHistogram) With(labelValues ...string) metrics.Histogram { return h }
func (h *NoopHistogram) Observe(value float64)                        {}
