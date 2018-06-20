package health_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"testing"
	"time"

	. "github.com/cloudtrust/flaki-service/pkg/health"
	"github.com/cloudtrust/flaki-service/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestEndpointLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var m = MakeEndpointLoggingMW(mockLogger)(MakeExecInfluxHealthCheckEndpoint(mockComponent))

	// Context with correlation ID.
	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var rep = json.RawMessage(`{"JSON":"MOCK_CONTENT"}`)

	// With correlation ID.
	mockLogger.EXPECT().Log("correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	mockComponent.EXPECT().ExecInfluxHealthChecks(ctx).Return(rep).Times(1)
	m(ctx, nil)

	// Without correlation ID.
	mockComponent.EXPECT().ExecInfluxHealthChecks(context.Background()).Return(rep).Times(1)
	var f = func() {
		m(context.Background(), nil)
	}
	assert.Panics(t, f)
}

func TestComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewHealthChecker(mockCtrl)

	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	rand.Seed(time.Now().UnixNano())
	var corrID = strconv.FormatUint(rand.Uint64(), 10)
	var ctx = context.WithValue(context.Background(), "correlation_id", corrID)
	var rep = json.RawMessage(`{"JSON":"MOCK_CONTENT"}`)

	// InfluxHealthChecks.
	{
		mockComponent.EXPECT().ExecInfluxHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ExecInfluxHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ExecInfluxHealthChecks(ctx)

		mockComponent.EXPECT().ReadInfluxHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ReadInfluxHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ReadInfluxHealthChecks(ctx)

		// Without correlation ID.
		mockComponent.EXPECT().ExecInfluxHealthChecks(context.Background()).Return(rep).Times(1)
		var f = func() {
			m.ExecInfluxHealthChecks(context.Background())
		}
		assert.Panics(t, f)

		mockComponent.EXPECT().ReadInfluxHealthChecks(context.Background()).Return(rep).Times(1)
		var g = func() {
			m.ReadInfluxHealthChecks(context.Background())
		}
		assert.Panics(t, g)
	}

	// JaegerHealthChecks.
	{
		mockComponent.EXPECT().ExecJaegerHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ExecJaegerHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ExecJaegerHealthChecks(ctx)

		mockComponent.EXPECT().ReadJaegerHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ReadJaegerHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ReadJaegerHealthChecks(ctx)

		// Without correlation ID.
		mockComponent.EXPECT().ExecJaegerHealthChecks(context.Background()).Return(rep).Times(1)
		var f = func() {
			m.ExecJaegerHealthChecks(context.Background())
		}
		assert.Panics(t, f)

		mockComponent.EXPECT().ReadJaegerHealthChecks(context.Background()).Return(rep).Times(1)
		var g = func() {
			m.ReadJaegerHealthChecks(context.Background())
		}
		assert.Panics(t, g)
	}

	// RedisHealthChecks.
	{
		mockComponent.EXPECT().ExecRedisHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ExecRedisHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ExecRedisHealthChecks(ctx)

		mockComponent.EXPECT().ReadRedisHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ReadRedisHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ReadRedisHealthChecks(ctx)

		// Without correlation ID.
		mockComponent.EXPECT().ExecRedisHealthChecks(context.Background()).Return(rep).Times(1)
		var f = func() {
			m.ExecRedisHealthChecks(context.Background())
		}
		assert.Panics(t, f)

		mockComponent.EXPECT().ReadRedisHealthChecks(context.Background()).Return(rep).Times(1)
		var g = func() {
			m.ReadRedisHealthChecks(context.Background())
		}
		assert.Panics(t, g)
	}

	// SentryHealthChecks.
	{
		mockComponent.EXPECT().ExecSentryHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ExecSentryHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ExecSentryHealthChecks(ctx)

		mockComponent.EXPECT().ReadSentryHealthChecks(ctx).Return(rep).Times(1)
		mockLogger.EXPECT().Log("unit", "ReadSentryHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.ReadSentryHealthChecks(ctx)

		// Without correlation ID.
		mockComponent.EXPECT().ExecSentryHealthChecks(context.Background()).Return(rep).Times(1)
		var f = func() {
			m.ExecSentryHealthChecks(context.Background())
		}
		assert.Panics(t, f)

		mockComponent.EXPECT().ReadSentryHealthChecks(context.Background()).Return(rep).Times(1)
		var g = func() {
			m.ReadSentryHealthChecks(context.Background())
		}
		assert.Panics(t, g)
	}

	// AllHealthChecks.
	{
		var report = json.RawMessage(`{"influx":[{"Name":"sentry","Duration":"1s","Status":"OK","Error":""}], "redis":[{"Name":"redis","Duration":"1s","Status":"OK","Error":""}]}`)
		mockComponent.EXPECT().AllHealthChecks(ctx).Return(report).Times(1)
		mockLogger.EXPECT().Log("unit", "AllHealthChecks", "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
		m.AllHealthChecks(ctx)

		// Without correlation ID.
		mockComponent.EXPECT().AllHealthChecks(context.Background()).Return(report).Times(1)
		var f = func() {
			m.AllHealthChecks(context.Background())
		}
		assert.Panics(t, f)
	}
}
