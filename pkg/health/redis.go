package health

//go:generate mockgen -destination=./mock/redis.go -package=mock -mock_names=RedisModule=RedisModule,Redis=Redis github.com/cloudtrust/keycloak-bridge/pkg/health RedisModule,Redis

import (
	"context"
	"time"
)

// RedisModule is the health check module for redis.
type RedisModule interface {
	HealthChecks(context.Context) []RedisHealthReport
}

type redisModule struct {
	redis Redis
}

// RedisHealthReport is the health report returned by the redis module.
type RedisHealthReport struct {
	Name     string
	Duration string
	Status   Status
	Error    string
}

// Redis is the interface of the redis client.
type Redis interface {
	Do(cmd string, args ...interface{}) (interface{}, error)
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
