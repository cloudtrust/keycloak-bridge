package health_test

import (
	"context"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInfluxModule = mock.NewInfluxModule(mockCtrl)
	var mockJaegerModule = mock.NewJaegerModule(mockCtrl)
	var mockRedisModule = mock.NewRedisModule(mockCtrl)
	var mockSentryModule = mock.NewSentryModule(mockCtrl)
	var mockKeycoakModule = mock.NewKeycloakModule(mockCtrl)

	mockInfluxModule.EXPECT().HealthChecks(context.Background()).Return([]InfluxReport{{Name: "influx", Duration: (1 * time.Second).String(), Status: OK}}).Times(2)
	mockJaegerModule.EXPECT().HealthChecks(context.Background()).Return([]JaegerReport{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: OK}}).Times(2)
	mockRedisModule.EXPECT().HealthChecks(context.Background()).Return([]RedisReport{{Name: "redis", Duration: (1 * time.Second).String(), Status: OK}}).Times(2)
	mockSentryModule.EXPECT().HealthChecks(context.Background()).Return([]SentryReport{{Name: "sentry", Duration: (1 * time.Second).String(), Status: OK}}).Times(2)
	mockKeycoakModule.EXPECT().HealthChecks(context.Background()).Return([]KeycloakReport{{Name: "keycloak", Duration: (1 * time.Second).String(), Status: OK}}).Times(2)

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule, mockKeycoakModule)

	// Influx.
	{
		var report = c.InfluxHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "influx", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// Jaeger.
	{
		var report = c.JaegerHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "jaeger", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// Redis.
	{
		var report = c.RedisHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "redis", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// Sentry.
	{
		var report = c.SentryHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "sentry", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// Keycloak.
	{
		var report = c.KeycloakHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "keycloak", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// All.
	{
		var reply = c.AllHealthChecks(context.Background())
		assert.Equal(t, "OK", reply["influx"])
		assert.Equal(t, "OK", reply["jaeger"])
		assert.Equal(t, "OK", reply["keycloak"])
		assert.Equal(t, "OK", reply["redis"])
		assert.Equal(t, "OK", reply["sentry"])
	}
}

func TestHealthChecksFail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInfluxModule = mock.NewInfluxModule(mockCtrl)
	var mockJaegerModule = mock.NewJaegerModule(mockCtrl)
	var mockRedisModule = mock.NewRedisModule(mockCtrl)
	var mockSentryModule = mock.NewSentryModule(mockCtrl)
	var mockKeycoakModule = mock.NewKeycloakModule(mockCtrl)

	mockInfluxModule.EXPECT().HealthChecks(context.Background()).Return([]InfluxReport{{Name: "influx", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}).Times(2)
	mockJaegerModule.EXPECT().HealthChecks(context.Background()).Return([]JaegerReport{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: Deactivated, Error: "fail"}}).Times(2)
	mockRedisModule.EXPECT().HealthChecks(context.Background()).Return([]RedisReport{{Name: "redis", Duration: (1 * time.Second).String(), Status: Degraded, Error: "fail"}}).Times(2)
	mockSentryModule.EXPECT().HealthChecks(context.Background()).Return([]SentryReport{{Name: "sentry", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}).Times(2)
	mockKeycoakModule.EXPECT().HealthChecks(context.Background()).Return([]KeycloakReport{{Name: "keycloak", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}).Times(2)

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule, mockKeycoakModule)

	// Influx.
	{
		var report = c.InfluxHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "influx", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, KO, report.Status)
		assert.Equal(t, "fail", report.Error)
	}

	// Jaeger.
	{
		var report = c.JaegerHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "jaeger", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, Deactivated, report.Status)
		assert.Equal(t, "fail", report.Error)
	}

	// Redis.
	{
		var report = c.RedisHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "redis", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, Degraded, report.Status)
		assert.Equal(t, "fail", report.Error)
	}

	// Sentry.
	{
		var report = c.SentryHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "sentry", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, KO, report.Status)
		assert.Equal(t, "fail", report.Error)
	}

	// Keycloak.
	{
		var report = c.KeycloakHealthChecks(context.Background()).Reports[0]
		assert.Equal(t, "keycloak", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, KO, report.Status)
		assert.Equal(t, "fail", report.Error)
	}

	// All.
	{
		var reply = c.AllHealthChecks(context.Background())
		assert.Equal(t, "KO", reply["influx"])
		assert.Equal(t, "Deactivated", reply["jaeger"])
		assert.Equal(t, "KO", reply["keycloak"])
		assert.Equal(t, "Degraded", reply["redis"])
		assert.Equal(t, "KO", reply["sentry"])
	}
}
