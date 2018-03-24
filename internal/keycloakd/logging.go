package keycloakd

//go:generate mockgen -source=logging.go -destination=./mock/logging.go -package=mock -mock_names=Redis=Redis github.com/cloudtrust/keycloak-bridge/cmd Redis

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// logstashLog is the logstash log format.
type logstashLog struct {
	Timestamp       string            `json:"@timestamp"`
	LogstashVersion int               `json:"@version"`
	Fields          map[string]string `json:"@fields"`
	Message         string            `json:"@message, omitempty"`
}

// RedisWriter encodes logs in logstash format and writes them to Redis.
type RedisWriter struct {
	redis Redis
	key   string
}

// Redis is the redis client interface.
type Redis interface {
	Send(commandName string, args ...interface{}) error
}

// NewLogstashRedisWriter returns a writer that writes logs into a redis DB.
func NewLogstashRedisWriter(redis Redis, key string) *RedisWriter {
	return &RedisWriter{
		redis: redis,
		key:   key,
	}
}

// Write encodes logs in logstash format and writes them to Redis.
func (w *RedisWriter) Write(data []byte) (int, error) {
	// The current logs are JSON formatted by the go-kit JSONLogger.
	var logs = make(map[string]string)
	{
		var err = json.Unmarshal(data, &logs)
		if err != nil {
			return 0, errors.Wrap(err, "could not decode JSON logs")
		}
	}

	// Encode to logstash format.
	var logstashLog []byte
	{
		var err error
		logstashLog, err = logstashEncode(logs)
		if err != nil {
			return 0, errors.Wrap(err, "could not encode logs to logstash format")
		}
	}

	// Write to Redis.
	var err = w.redis.Send("RPUSH", w.key, logstashLog)
	if err != nil {
		return 0, errors.Wrap(err, "could not write logs to Redis")
	}
	return len(data), nil
}

func logstashEncode(m map[string]string) ([]byte, error) {
	var timestamp = m["ts"]
	delete(m, "ts")
	var msg = m["msg"]
	delete(m, "msg")

	var l = logstashLog{
		Timestamp:       timestamp,
		LogstashVersion: 1,
		Fields:          m,
		Message:         msg,
	}

	return json.Marshal(l)
}

// NoopRedis is a Redis client that does nothing.
type NoopRedis struct{}

// Close does nothing.
func (r *NoopRedis) Close() error { return nil }

// Do does nothing.
func (r *NoopRedis) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	return nil, nil
}

// Send does nothing.
func (r *NoopRedis) Send(commandName string, args ...interface{}) error { return nil }

// Flush does nothing.
func (r *NoopRedis) Flush() error { return nil }
