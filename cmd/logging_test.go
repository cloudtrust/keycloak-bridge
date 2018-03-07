package main

import (
	"encoding/json"
	"testing"

	"github.com/cloudtrust/flaki-service/cmd/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestLogstashRedisWriter(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockRedis = mock.NewRedis(mockCtrl)

	var w = NewLogstashRedisWriter(mockRedis, "redisKey")

	var jsonLog = "{\"msg\":\"logstash log\",\"caller\":\"flakid.go:120\",\"component_name\":\"flaki-service\",\"component_version\":\"1.0.0\",\"environment\":\"DEV\",\"git_commit\":\"5fb7de0d7ae3f3d5f5d6a322b2344bdab645fd33\",\"ts\":\"2018-02-13T06:27:07.123915229Z\"}"
	mockRedis.EXPECT().Send("RPUSH", "redisKey", gomock.Any()).Return(nil).Times(1)
	w.Write([]byte(jsonLog))
}

func TestLogstashEncode(t *testing.T) {
	var logs = map[string]string{
		"msg":               "logstash log",
		"caller":            "flakid.go:120",
		"component_name":    "flaki-service",
		"component_version": "1.0.0",
		"environment":       "DEV",
		"git_commit":        "5fb7de0d7ae3f3d5f5d6a322b2344bdab645fd33",
		"ts":                "2018-02-13T06:27:07.123915229Z",
	}

	var logstashLog, err = logstashEncode(logs)
	assert.Nil(t, err)

	var m = map[string]interface{}{}
	json.Unmarshal(logstashLog, &m)

	assert.Equal(t, "2018-02-13T06:27:07.123915229Z", m["@timestamp"])
	assert.Equal(t, float64(1), m["@version"])
	assert.Equal(t, "logstash log", m["@message"])

	var fields = m["@fields"].(map[string]interface{})
	assert.Equal(t, "flakid.go:120", fields["caller"])
	assert.Equal(t, "flaki-service", fields["component_name"])
	assert.Equal(t, "1.0.0", fields["component_version"])
	assert.Equal(t, "DEV", fields["environment"])
	assert.Equal(t, "5fb7de0d7ae3f3d5f5d6a322b2344bdab645fd33", fields["git_commit"])
	var _, ok = fields["ts"]
	assert.False(t, ok)
	_, ok = fields["msg"]
	assert.False(t, ok)
}
