package health_test

//go:generate mockgen -destination=./mock/module.go -package=mock -mock_names=HealthChecker=HealthChecker,HealthCheckStorage=HealthCheckStorage  github.com/cloudtrust/keycloak-bridge/pkg/health HealthChecker,HealthCheckStorage

import (
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func reportIndent(s json.RawMessage) json.RawMessage {
	var report, err = json.MarshalIndent(s, "", "  ")
	if err != nil {
		panic("could not marshal report")
	}
	return report
}

func TestHealthChecksWithCache(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockCockroachHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockInfluxHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockJaegerHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockStorage = mock.NewHealthCheckStorage(mockCtrl)

	var (
		validity = map[string]time.Duration{
			"cockroach": 1 * time.Minute,
			"influx":    2 * time.Minute,
			"jaeger":    3 * time.Minute,
		}
		healthCheckModules = map[string]HealthChecker{
			"cockroach": mockCockroachHealthChecker,
			"influx":    mockInfluxHealthChecker,
			"jaeger":    mockJaegerHealthChecker,
		}
		corrID          = strconv.FormatUint(rand.Uint64(), 10)
		ctx             = context.WithValue(context.Background(), "correlation_id", corrID)
		cockroachReport = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
		influxReport    = reportIndent(json.RawMessage(`[{"name": "ping influx","status": "OK","duration": "1ms"}]`))
		jaegerReport    = reportIndent(json.RawMessage(`[{"name": "ping jaeger agent","status": "OK","duration": "1ms"},{"name": "ping jaeger collector","status": "OK","duration": "1ms"}]`))
	)

	var c = NewComponent(healthCheckModules, validity, mockStorage)

	mockStorage.EXPECT().Read(ctx, "cockroach", "ping").Return(cockroachReport, nil).Times(1)
	{
		var req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			// When there is no parameter 'nocache=1', the cache is used.
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, cockroachReport, report)
	}

	mockStorage.EXPECT().Read(ctx, "influx", "ping").Return(influxReport, nil).Times(1)
	{
		var req = map[string]string{
			"module":      "influx",
			"healthcheck": "ping",
			// When there is no parameter 'nocache=1', the cache is used.
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, influxReport, report)
	}

	mockStorage.EXPECT().Read(ctx, "jaeger", "ping").Return(jaegerReport, nil).Times(1)
	{
		var req = map[string]string{
			"module":      "jaeger",
			"healthcheck": "ping",
			// When there is no parameter 'nocache=1', the cache is used.
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, jaegerReport, report)
	}

	// All health checks
	mockStorage.EXPECT().Read(ctx, "cockroach", "").Return(cockroachReport, nil).Times(1)
	mockStorage.EXPECT().Read(ctx, "influx", "").Return(influxReport, nil).Times(1)
	mockStorage.EXPECT().Read(ctx, "jaeger", "").Return(jaegerReport, nil).Times(1)
	{
		var req = map[string]string{
			"module":      "",
			"healthcheck": "",
			// When there is no parameter 'nocache=1', the cache is used.
		}
		var jsonReports, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)

		var reports = map[string]json.RawMessage{}
		json.Unmarshal(jsonReports, &reports)

		// Check report ignoring whitespaces (there is an issue when unmarshaling to map[string]json.RawMessage{}.
		// The indentation is not striclty equal, which break the equality check.

		// Cockroach
		{
			var expected = removeWhitspaces(string(cockroachReport))
			var actual = removeWhitspaces(string(reports["cockroach"]))

			assert.Equal(t, expected, actual)
		}
		// Influx
		{
			var expected = removeWhitspaces(string(influxReport))
			var actual = removeWhitspaces(string(reports["influx"]))

			assert.Equal(t, expected, actual)
		}
		// Jaeger
		{
			var expected = removeWhitspaces(string(jaegerReport))
			var actual = removeWhitspaces(string(reports["jaeger"]))

			assert.Equal(t, expected, actual)
		}
	}
}

func TestHealthChecksWithoutCache(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockCockroachHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockInfluxHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockJaegerHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockStorage = mock.NewHealthCheckStorage(mockCtrl)

	var (
		validity = map[string]time.Duration{
			"cockroach": 1 * time.Minute,
			"influx":    2 * time.Minute,
			"jaeger":    3 * time.Minute,
		}
		healthCheckModules = map[string]HealthChecker{
			"cockroach": mockCockroachHealthChecker,
			"influx":    mockInfluxHealthChecker,
			"jaeger":    mockJaegerHealthChecker,
		}
		corrID          = strconv.FormatUint(rand.Uint64(), 10)
		ctx             = context.WithValue(context.Background(), "correlation_id", corrID)
		cockroachReport = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
		influxReport    = reportIndent(json.RawMessage(`[{"name": "ping influx","status": "OK","duration": "1ms"}]`))
		jaegerReport    = reportIndent(json.RawMessage(`[{"name": "ping jaeger agent","status": "OK","duration": "1ms"},{"name": "ping jaeger collector","status": "OK","duration": "1ms"}]`))
	)

	var c = NewComponent(healthCheckModules, validity, mockStorage)

	mockCockroachHealthChecker.EXPECT().HealthCheck(ctx, "ping").Return(cockroachReport, nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "cockroach", cockroachReport, validity["cockroach"]).Return(nil).Times(1)
	{
		var req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, cockroachReport, report)
	}

	mockInfluxHealthChecker.EXPECT().HealthCheck(ctx, "ping").Return(influxReport, nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "influx", influxReport, validity["influx"]).Return(nil).Times(1)
	{
		var req = map[string]string{
			"module":      "influx",
			"healthcheck": "ping",
			"nocache":     "1",
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, influxReport, report)
	}

	mockJaegerHealthChecker.EXPECT().HealthCheck(ctx, "ping").Return(jaegerReport, nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "jaeger", jaegerReport, validity["jaeger"]).Return(nil).Times(1)
	{
		var req = map[string]string{
			"module":      "jaeger",
			"healthcheck": "ping",
			"nocache":     "1",
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, jaegerReport, report)
	}

	// All health checks
	mockCockroachHealthChecker.EXPECT().HealthCheck(ctx, "").Return(cockroachReport, nil).Times(1)
	mockInfluxHealthChecker.EXPECT().HealthCheck(ctx, "").Return(influxReport, nil).Times(1)
	mockJaegerHealthChecker.EXPECT().HealthCheck(ctx, "").Return(jaegerReport, nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "cockroach", cockroachReport, validity["cockroach"]).Return(nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "influx", influxReport, validity["influx"]).Return(nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "jaeger", jaegerReport, validity["jaeger"]).Return(nil).Times(1)
	{
		var req = map[string]string{
			"module":      "",
			"healthcheck": "",
			"nocache":     "1",
		}
		var jsonReports, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)

		var reports = map[string]json.RawMessage{}
		json.Unmarshal(jsonReports, &reports)

		// Check report ignoring whitespaces (there is an issue when unmarshaling to map[string]json.RawMessage{}.
		// The indentation is not striclty equal, which break the equality check.

		// Cockroach
		{
			var expected = removeWhitspaces(string(cockroachReport))
			var actual = removeWhitspaces(string(reports["cockroach"]))

			assert.Equal(t, expected, actual)
		}
		// Influx
		{
			var expected = removeWhitspaces(string(influxReport))
			var actual = removeWhitspaces(string(reports["influx"]))

			assert.Equal(t, expected, actual)
		}
		// Jaeger
		{
			var expected = removeWhitspaces(string(jaegerReport))
			var actual = removeWhitspaces(string(reports["jaeger"]))

			assert.Equal(t, expected, actual)
		}
	}
}

func TestHealthChecksReportInvalid(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockCockroachHealthChecker = mock.NewHealthChecker(mockCtrl)
	var mockStorage = mock.NewHealthCheckStorage(mockCtrl)

	var (
		validity = map[string]time.Duration{
			"cockroach": 1 * time.Minute,
		}
		healthCheckModules = map[string]HealthChecker{
			"cockroach": mockCockroachHealthChecker,
		}
		corrID = strconv.FormatUint(rand.Uint64(), 10)
		ctx    = context.WithValue(context.Background(), "correlation_id", corrID)
	)

	var c = NewComponent(healthCheckModules, validity, mockStorage)

	var (
		cockroachReport = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
	)

	mockStorage.EXPECT().Read(ctx, "cockroach", "ping").Return(nil, ErrInvalid).Times(1)
	mockCockroachHealthChecker.EXPECT().HealthCheck(ctx, "ping").Return(cockroachReport, nil).Times(1)
	mockStorage.EXPECT().Update(ctx, "cockroach", cockroachReport, validity["cockroach"]).Return(nil).Times(1)
	{
		var req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
		}

		var report, err = c.HealthChecks(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, cockroachReport, report)
	}
}

func removeWhitspaces(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(s))
}
