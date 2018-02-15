package health

import (
	"context"
	"time"
)

type RedisModule interface {
	HealthChecks(context.Context) []RedisHealthReport
}

type RedisHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

type Redis interface {
	Do(cmd string, args ...interface{}) (interface{}, error)
}

type redisModule struct {
	redis Redis
}

// NewRedisModule returns the redis health module.
func NewRedisModule(redis Redis) RedisModule {
	return &redisModule{redis: redis}
}

// HealthChecks executes all health checks for Redis.
func (m *redisModule) HealthChecks(context.Context) []RedisHealthReport {
	var reports = []RedisHealthReport{}
	reports = append(reports, redisPingCheck(m.redis))
	return reports
}

func redisPingCheck(redis Redis) RedisHealthReport {
	// If redis is deactivated.
	if redis == nil {
		return RedisHealthReport{
			Name:     "ping",
			Duration: "N/A",
			Status:   Deactivated,
		}
	}

	var now = time.Now()
	var _, err = redis.Do("PING")
	var duration = time.Since(now)

	var status = OK
	var error = ""
	if err != nil {
		status = KO
		error = err.Error()
	}

	return RedisHealthReport{
		Name:     "ping",
		Duration: duration.String(),
		Status:   status,
		Error:    error,
	}
}
