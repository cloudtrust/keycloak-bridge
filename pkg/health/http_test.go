package health

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthCheckHandler(t *testing.T) {

	var h = MakeInfluxHealthCheckHandler(MakeMockHealthEndpoint("influx", false))

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/influx", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m = map[string]interface{}{}
	json.Unmarshal(body, &m)

	var r = m["health checks"].([]interface{})[0]
	{
		var m = r.(map[string]interface{})
		assert.Equal(t, "influx", m["name"])
		assert.NotZero(t, m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}
func TestJaegerHealthCheckHandler(t *testing.T) {

	var h = MakeJaegerHealthCheckHandler(MakeMockHealthEndpoint("jaeger", false))

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/jaeger", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m = map[string]interface{}{}
	json.Unmarshal(body, &m)

	var r = m["health checks"].([]interface{})[0]
	{
		var m = r.(map[string]interface{})
		assert.Equal(t, "jaeger", m["name"])
		assert.NotZero(t, m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestRedisHealthCheckHandler(t *testing.T) {

	var h = MakeRedisHealthCheckHandler(MakeMockHealthEndpoint("redis", false))

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/redis", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m = map[string]interface{}{}
	json.Unmarshal(body, &m)

	var r = m["health checks"].([]interface{})[0]
	{
		var m = r.(map[string]interface{})
		assert.Equal(t, "redis", m["name"])
		assert.NotZero(t, m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}
func TestSentryHealthCheckHandler(t *testing.T) {

	var h = MakeSentryHealthCheckHandler(MakeMockHealthEndpoint("sentry", false))

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/sentry", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m = map[string]interface{}{}
	json.Unmarshal(body, &m)

	var r = m["health checks"].([]interface{})[0]
	{
		var m = r.(map[string]interface{})
		assert.Equal(t, "sentry", m["name"])
		assert.NotZero(t, m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestHealthChecksHandler(t *testing.T) {
	var influxE = MakeMockHealthEndpoint("influx", false)
	var jaegerE = MakeMockHealthEndpoint("jaeger", false)
	var redisE = MakeMockHealthEndpoint("redis", false)
	var sentryE = MakeMockHealthEndpoint("sentry", false)

	var es = Endpoints{
		InfluxHealthCheck: influxE,
		JaegerHealthCheck: jaegerE,
		RedisHealthCheck:  redisE,
		SentryHealthCheck: sentryE,
	}

	var h = MakeHealthChecksHandler(es)

	// HTTP request.
	var s = httptest.NewServer(http.HandlerFunc(h))
	defer s.Close()

	// Health check.
	var resp, err = s.Client().Get(s.URL)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var body []byte
	{
		var err error
		body, err = ioutil.ReadAll(resp.Body)
		assert.Nil(t, err)
		var m = map[string]string{}
		json.Unmarshal(body, &m)
		assert.Equal(t, "OK", m["influx"])
		assert.Equal(t, "OK", m["jaeger"])
		assert.Equal(t, "OK", m["redis"])
		assert.Equal(t, "OK", m["sentry"])
	}
}
func TestHealthChecksHandlerFail(t *testing.T) {
	var influxE = MakeMockHealthEndpoint("influx", true)
	var jaegerE = MakeMockHealthEndpoint("jaeger", true)
	var redisE = MakeMockHealthEndpoint("redis", true)
	var sentryE = MakeMockHealthEndpoint("sentry", true)

	var es = Endpoints{
		InfluxHealthCheck: influxE,
		JaegerHealthCheck: jaegerE,
		RedisHealthCheck:  redisE,
		SentryHealthCheck: sentryE,
	}

	var h = MakeHealthChecksHandler(es)

	// HTTP request.
	var s = httptest.NewServer(http.HandlerFunc(h))
	defer s.Close()

	// Health check.
	var resp, err = s.Client().Get(s.URL)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var body []byte
	{
		var err error
		body, err = ioutil.ReadAll(resp.Body)
		assert.Nil(t, err)
		var m = map[string]string{}
		json.Unmarshal(body, &m)
		assert.Equal(t, "KO", m["influx"])
		assert.Equal(t, "KO", m["jaeger"])
		assert.Equal(t, "KO", m["redis"])
		assert.Equal(t, "KO", m["sentry"])
	}
}
func TestHTTPErrorHandler(t *testing.T) {
	var e = func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return nil, fmt.Errorf("fail")
	}

	var h = MakeInfluxHealthCheckHandler(e)

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/sentry", nil)
	var w = httptest.NewRecorder()

	// Health checks.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "500 Internal Server Error", string(body))
}
