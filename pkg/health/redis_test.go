package health

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRedisHealthChecks(t *testing.T) {
	var mockRedis = &mockRedis{fail: false}

	var m = NewRedisModule(mockRedis)

	mockRedis.called = false
	var report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockRedis.called)
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, OK, report.Status)
	assert.Zero(t, report.Error)

	// Redis fail.
	mockRedis.fail = true
	mockRedis.called = false
	report = m.HealthChecks(context.Background())[0]
	assert.True(t, mockRedis.called)
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, KO, report.Status)
	assert.NotZero(t, report.Error)
}
func TestNoopRedisHealthChecks(t *testing.T) {
	var m = NewRedisModule(nil)

	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)

}

// Mock Redis.
type mockRedis struct {
	called bool
	fail   bool
}

func (r *mockRedis) Do(cmd string, args ...interface{}) (interface{}, error) {
	r.called = true
	if r.fail {
		return nil, fmt.Errorf("fail")
	}
	return nil, nil
}

// Mock Redis module.
type mockRedisModule struct {
	fail bool
}

func (m *mockRedisModule) HealthChecks(context.Context) []RedisHealthReport {
	if m.fail {
		return []RedisHealthReport{RedisHealthReport{
			Name:     "redis",
			Duration: time.Duration(1 * time.Second).String(),
			Status:   KO,
			Error:    "fail",
		}}
	}
	return []RedisHealthReport{RedisHealthReport{
		Name:     "redis",
		Duration: time.Duration(1 * time.Second).String(),
		Status:   OK,
	}}
}
