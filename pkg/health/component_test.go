package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHealthChecks(t *testing.T) {
	var mockInfluxModule = &mockInfluxModule{fail: false}
	var mockJaegerModule = &mockJaegerModule{fail: false}
	var mockRedisModule = &mockRedisModule{fail: false}
	var mockSentryModule = &mockSentryModule{fail: false}

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule)

	// Influx.
	var ir = c.InfluxHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "influx", ir.Name)
	assert.NotZero(t, ir.Duration)
	assert.Equal(t, OK, ir.Status)
	assert.Zero(t, ir.Error)

	// Jaeger.
	var jr = c.JaegerHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "jaeger", jr.Name)
	assert.NotZero(t, jr.Duration)
	assert.Equal(t, OK, jr.Status)
	assert.Zero(t, jr.Error)

	// Redis.
	var rr = c.RedisHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "redis", rr.Name)
	assert.NotZero(t, rr.Duration)
	assert.Equal(t, OK, rr.Status)
	assert.Zero(t, rr.Error)

	// Sentry.
	var sr = c.SentryHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "sentry", sr.Name)
	assert.NotZero(t, sr.Duration)
	assert.Equal(t, OK, sr.Status)
	assert.Zero(t, sr.Error)
}
func TestHealthChecksFail(t *testing.T) {
	var mockInfluxModule = &mockInfluxModule{fail: true}
	var mockJaegerModule = &mockJaegerModule{fail: true}
	var mockRedisModule = &mockRedisModule{fail: true}
	var mockSentryModule = &mockSentryModule{fail: true}

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule)

	// Influx.
	var ir = c.InfluxHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "influx", ir.Name)
	assert.NotZero(t, ir.Duration)
	assert.Equal(t, KO, ir.Status)
	assert.Equal(t, "fail", ir.Error)

	// Jaeger.
	var jr = c.JaegerHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "jaeger", jr.Name)
	assert.NotZero(t, jr.Duration)
	assert.Equal(t, KO, jr.Status)
	assert.Equal(t, "fail", jr.Error)

	// Redis.
	var rr = c.RedisHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "redis", rr.Name)
	assert.NotZero(t, rr.Duration)
	assert.Equal(t, KO, rr.Status)
	assert.Equal(t, "fail", rr.Error)

	// Sentry.
	var sr = c.SentryHealthChecks(context.Background()).Reports[0]
	assert.Equal(t, "sentry", sr.Name)
	assert.NotZero(t, sr.Duration)
	assert.Equal(t, KO, sr.Status)
	assert.Equal(t, "fail", sr.Error)
}

// Mock component.
type mockComponent struct {
	fail         bool
	influxCalled bool
	jaegerCalled bool
	redisCalled  bool
	sentryCalled bool
}

func (c *mockComponent) InfluxHealthChecks(context.Context) HealthReports {
	var r = HealthReport{
		Name:     "influx",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
		Error:    "",
	}

	if c.fail {
		r.Status = KO
		r.Error = "fail"
	}

	return HealthReports{Reports: []HealthReport{r}}
}

func (c *mockComponent) JaegerHealthChecks(context.Context) HealthReports {
	var r = HealthReport{
		Name:     "jaeger",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
		Error:    "",
	}

	if c.fail {
		r.Status = KO
		r.Error = "fail"
	}

	return HealthReports{Reports: []HealthReport{r}}
}
func (c *mockComponent) RedisHealthChecks(context.Context) HealthReports {
	var r = HealthReport{
		Name:     "redis",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
		Error:    "",
	}

	if c.fail {
		r.Status = KO
		r.Error = "fail"
	}

	return HealthReports{Reports: []HealthReport{r}}
}
func (c *mockComponent) SentryHealthChecks(context.Context) HealthReports {
	var r = HealthReport{
		Name:     "sentry",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
		Error:    "",
	}

	if c.fail {
		r.Status = KO
		r.Error = "fail"
	}

	return HealthReports{Reports: []HealthReport{r}}
}
