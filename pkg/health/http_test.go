package health_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheckHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthCheckers(mockCtrl)

	var h = MakeHealthCheckHandler(MakeHealthChecksEndpoint(mockComponent))

	var route = mux.NewRouter()
	// Health checks.
	route.Path("/health").Handler(h)
	route.Path("/health/{module}").Handler(h)
	route.Path("/health/{module}/{healthcheck}").Handler(h)
	route.Path("/health").Queries("nocache", "{nocache}").Handler(h)
	route.Path("/health/{module}").Queries("nocache", "{nocache}").Handler(h)
	route.Path("/health/{module}/{healthcheck}").Queries("nocache", "{nocache}").Handler(h)

	var (
		req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}
		cockroachReport = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
	)

	mockComponent.EXPECT().HealthChecks(gomock.Any(), req).Return(cockroachReport, nil).Times(1)

	// HTTP request.
	var httpReq = httptest.NewRequest("GET", "/health/cockroach/ping?nocache=1", nil)
	var w = httptest.NewRecorder()

	// Health check.
	route.ServeHTTP(w, httpReq)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, cockroachReport, json.RawMessage(body))
}

func TestHTTPErrorHandler(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthCheckers(mockCtrl)

	var h = MakeHealthCheckHandler(MakeHealthChecksEndpoint(mockComponent))

	var route = mux.NewRouter()
	// Health checks.
	route.Path("/health").Handler(h)
	route.Path("/health/{module}").Handler(h)
	route.Path("/health/{module}/{healthcheck}").Handler(h)
	route.Path("/health").Queries("nocache", "{nocache}").Handler(h)
	route.Path("/health/{module}").Queries("nocache", "{nocache}").Handler(h)
	route.Path("/health/{module}/{healthcheck}").Queries("nocache", "{nocache}").Handler(h)

	var (
		req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}
		errorMsg = reportIndent(json.RawMessage(`{"error": "fail"}`))
	)

	mockComponent.EXPECT().HealthChecks(gomock.Any(), req).Return(nil, fmt.Errorf("fail")).Times(1)

	// HTTP request.
	var httpReq = httptest.NewRequest("GET", "/health/cockroach/ping?nocache=1", nil)
	var w = httptest.NewRecorder()

	// Health check.
	route.ServeHTTP(w, httpReq)
	var resp = w.Result()
	var body, err = ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, errorMsg, json.RawMessage(body))
}
