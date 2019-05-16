package keycloakb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMetrics(t *testing.T) {
	// Will be removed using common-service
}

func TestNoopMetrics(t *testing.T) {
	var noopMetrics = &NoopMetrics{}

	assert.Nil(t, noopMetrics.Write(nil))

	var counter = noopMetrics.NewCounter("counter name")
	assert.IsType(t, &NoopCounter{}, counter)
	assert.IsType(t, &NoopCounter{}, counter.With())

	var gauge = noopMetrics.NewGauge("gauge name")
	assert.IsType(t, &NoopGauge{}, gauge)
	assert.IsType(t, &NoopGauge{}, gauge.With())

	var histogram = noopMetrics.NewHistogram("histogram name")
	assert.IsType(t, &NoopHistogram{}, histogram)
	assert.IsType(t, &NoopHistogram{}, histogram.With())

	var duration, s, err = noopMetrics.Ping(1 * time.Second)
	assert.Equal(t, time.Duration(0), duration)
	assert.Equal(t, "", s)
	assert.Nil(t, err)
}
