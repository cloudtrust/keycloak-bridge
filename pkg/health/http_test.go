package health_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var h = MakeInfluxHealthCheckHandler(MakeInfluxHealthCheckEndpoint(mockComponent))

	// Health success.
	mockComponent.EXPECT().InfluxHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "influx", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

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
		assert.Equal(t, (1 * time.Second).String(), m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}
func TestJaegerHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var h = MakeJaegerHealthCheckHandler(MakeJaegerHealthCheckEndpoint(mockComponent))

	// Health success.
	mockComponent.EXPECT().JaegerHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

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
		assert.Equal(t, (1 * time.Second).String(), m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestRedisHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var h = MakeRedisHealthCheckHandler(MakeRedisHealthCheckEndpoint(mockComponent))

	// Health success.
	mockComponent.EXPECT().RedisHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "redis", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

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
		assert.Equal(t, (1 * time.Second).String(), m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestSentryHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var h = MakeSentryHealthCheckHandler(MakeSentryHealthCheckEndpoint(mockComponent))

	// Health success.
	mockComponent.EXPECT().SentryHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "sentry", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

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
		assert.Equal(t, (1 * time.Second).String(), m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestKeycloakHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var h = MakeKeycloakHealthCheckHandler(MakeKeycloakHealthCheckEndpoint(mockComponent))

	// Health success.
	mockComponent.EXPECT().KeycloakHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "keycloak", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/keycloak", nil)
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
		assert.Equal(t, "keycloak", m["name"])
		assert.Equal(t, (1 * time.Second).String(), m["duration"])
		assert.Equal(t, "OK", m["status"])
		assert.Zero(t, m["error"])
	}
}

func TestHealthChecksHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	// Health success.
	mockComponent.EXPECT().InfluxHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "influx", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)
	mockComponent.EXPECT().JaegerHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)
	mockComponent.EXPECT().RedisHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "redis", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)
	mockComponent.EXPECT().SentryHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "sentry", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)
	mockComponent.EXPECT().KeycloakHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "keycloak", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	var es = Endpoints{
		InfluxHealthCheck:   MakeInfluxHealthCheckEndpoint(mockComponent),
		JaegerHealthCheck:   MakeJaegerHealthCheckEndpoint(mockComponent),
		RedisHealthCheck:    MakeRedisHealthCheckEndpoint(mockComponent),
		SentryHealthCheck:   MakeSentryHealthCheckEndpoint(mockComponent),
		KeycloakHealthCheck: MakeKeycloakHealthCheckEndpoint(mockComponent),
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
		assert.Equal(t, OK.String(), m["influx"])
		assert.Equal(t, OK.String(), m["jaeger"])
		assert.Equal(t, OK.String(), m["redis"])
		assert.Equal(t, OK.String(), m["sentry"])
		assert.Equal(t, OK.String(), m["keycloak"])
	}
}
func TestHealthChecksHandlerFail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	// Health fail.
	mockComponent.EXPECT().InfluxHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "influx", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)
	mockComponent.EXPECT().JaegerHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)
	mockComponent.EXPECT().RedisHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "redis", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)
	mockComponent.EXPECT().SentryHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "sentry", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)
	mockComponent.EXPECT().KeycloakHealthChecks(context.Background()).Return(Reports{Reports: []Report{{Name: "keycloak", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)

	var es = Endpoints{
		InfluxHealthCheck:   MakeInfluxHealthCheckEndpoint(mockComponent),
		JaegerHealthCheck:   MakeJaegerHealthCheckEndpoint(mockComponent),
		RedisHealthCheck:    MakeRedisHealthCheckEndpoint(mockComponent),
		SentryHealthCheck:   MakeSentryHealthCheckEndpoint(mockComponent),
		KeycloakHealthCheck: MakeKeycloakHealthCheckEndpoint(mockComponent),
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
		assert.Equal(t, KO.String(), m["influx"])
		assert.Equal(t, KO.String(), m["jaeger"])
		assert.Equal(t, KO.String(), m["redis"])
		assert.Equal(t, KO.String(), m["sentry"])
		assert.Equal(t, KO.String(), m["keycloak"])
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
	assert.Equal(t, "fail", string(body))
}
