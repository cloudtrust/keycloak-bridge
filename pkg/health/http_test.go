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
	"github.com/go-kit/kit/ratelimit"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestInfluxHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeExecInfluxHealthCheckEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`[{"Name":"influx","Duration":"1s","Status":"OK"}]`)
	mockComponent.EXPECT().ExecInfluxHealthChecks(context.Background()).Return(report).Times(1)

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

	var m []interface{}
	json.Unmarshal(body, &m)

	var r = m[0].(map[string]interface{})
	{
		assert.Equal(t, "influx", r["Name"])
		assert.Equal(t, (1 * time.Second).String(), r["Duration"])
		assert.Equal(t, "OK", r["Status"])
		assert.Zero(t, r["Error"])
	}
}

func TestJaegerHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeExecJaegerHealthCheckEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`[{"Name":"jaeger","Duration":"1s","Status":"OK"}]`)
	mockComponent.EXPECT().ExecJaegerHealthChecks(context.Background()).Return(report).Times(1)

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

	var m []interface{}
	json.Unmarshal(body, &m)

	var r = m[0].(map[string]interface{})
	{
		assert.Equal(t, "jaeger", r["Name"])
		assert.Equal(t, (1 * time.Second).String(), r["Duration"])
		assert.Equal(t, "OK", r["Status"])
		assert.Zero(t, r["Error"])
	}
}

func TestRedisHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeExecRedisHealthCheckEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`[{"Name":"redis","Duration":"1s","Status":"OK","Error":"Error occured"}]`)
	mockComponent.EXPECT().ExecRedisHealthChecks(context.Background()).Return(report).Times(1)

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

	var m []interface{}
	json.Unmarshal(body, &m)

	var r = m[0].(map[string]interface{})
	{
		assert.Equal(t, "redis", r["Name"])
		assert.Equal(t, (1 * time.Second).String(), r["Duration"])
		assert.Equal(t, "OK", r["Status"])
		assert.Equal(t, "Error occured", r["Error"])
	}
}

func TestSentryHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeExecSentryHealthCheckEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`[{"Name":"sentry","Duration":"1s","Status":"OK","Error":"Unexpected error"}]`)
	mockComponent.EXPECT().ExecSentryHealthChecks(context.Background()).Return(report).Times(1)

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

	var m []interface{}
	json.Unmarshal(body, &m)

	var r = m[0].(map[string]interface{})
	{
		assert.Equal(t, "sentry", r["Name"])
		assert.Equal(t, (1 * time.Second).String(), r["Duration"])
		assert.Equal(t, "OK", r["Status"])
		assert.Equal(t, "Unexpected error", r["Error"])
	}
}

func TestKeycloakHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeExecKeycloakHealthCheckEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`[{"Name":"keycloak","Duration":"1s","Status":"OK","Error":"Unexpected error"}]`)
	mockComponent.EXPECT().ExecKeycloakHealthChecks(context.Background()).Return(report).Times(1)

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

	var m []interface{}
	json.Unmarshal(body, &m)

	var r = m[0].(map[string]interface{})
	{
		assert.Equal(t, "keycloak", r["Name"])
		assert.Equal(t, (1 * time.Second).String(), r["Duration"])
		assert.Equal(t, "OK", r["Status"])
		assert.Equal(t, "Unexpected error", r["Error"])
	}
}

func TestHealthChecksHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeAllHealthChecksEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`{"influx":[{"Name":"sentry","Duration":"1s","Status":"OK","Error":""}], "redis":[{"Name":"redis","Duration":"1s","Status":"OK","Error":""}]}`)
	mockComponent.EXPECT().AllHealthChecks(context.Background()).Return(report).Times(1)

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m map[string]interface{}
	json.Unmarshal(body, &m)

	var r = m["influx"].([]interface{})
	var n = r[0].(map[string]interface{})
	{
		assert.Equal(t, "sentry", n["Name"])
		assert.Equal(t, (1 * time.Second).String(), n["Duration"])
		assert.Equal(t, "OK", n["Status"])
		assert.Equal(t, "", n["Error"])
	}
}

func TestHealthChecksHandlerFail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var h = MakeHealthCheckHandler(MakeAllHealthChecksEndpoint(mockComponent))

	// Health success.
	var report = json.RawMessage(`{"influx":[{"Name":"sentry","Duration":"1s","Status":"Deactivated","Error":""}], "redis":[{"Name":"redis","Duration":"1s","Status":"KO","Error":"Unexpected error"}]}`)
	mockComponent.EXPECT().AllHealthChecks(context.Background()).Return(report).Times(1)

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health", nil)
	var w = httptest.NewRecorder()

	// Health check.
	h.ServeHTTP(w, req)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))

	var m map[string]interface{}
	json.Unmarshal(body, &m)

	var r = m["influx"].([]interface{})
	var n = r[0].(map[string]interface{})
	{
		assert.Equal(t, "sentry", n["Name"])
		assert.Equal(t, (1 * time.Second).String(), n["Duration"])
		assert.Equal(t, "Deactivated", n["Status"])
		assert.Equal(t, "", n["Error"])
	}

	var v = m["redis"].([]interface{})
	var z = v[0].(map[string]interface{})
	{
		assert.Equal(t, "redis", z["Name"])
		assert.Equal(t, (1 * time.Second).String(), z["Duration"])
		assert.Equal(t, "KO", z["Status"])
		assert.Equal(t, "Unexpected error", z["Error"])
	}
}

func TestHTTPErrorHandler(t *testing.T) {
	var e = func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return nil, fmt.Errorf("fail")
	}

	var h = MakeHealthCheckHandler(e)

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
	// Decode JSON and check error value.
	{
		var m = map[string]string{}
		var err = json.Unmarshal(body, &m)
		assert.Nil(t, err)
		assert.Equal(t, "fail", m["error"])
	}
}

func TestTooManyRequests(t *testing.T) {
	var e = func(ctx context.Context, request interface{}) (response interface{}, err error) {
		return nil, nil
	}

	var rateLimit = 1

	e = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), rateLimit))(e)
	var h = MakeHealthCheckHandler(e)

	// HTTP request.
	var req = httptest.NewRequest("GET", "http://cloudtrust.io/health/sentry", nil)

	// Make too many requests, to trigger the rate limitation.
	var w *httptest.ResponseRecorder
	for i := 0; i < rateLimit+1; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}

	// Check the error returned by the rate limiter. The package ratelimit return the error
	// ErrLimited = errors.New("rate limit exceeded") when the rate is limited. In our http
	// package, we return a 429 status code when such an error arises.
	var resp = w.Result()
	var _, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}
