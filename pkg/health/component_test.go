package health_test

//go:generate mockgen -destination=./mock/es.go -package=mock -mock_names=ESHealthChecker=ESHealthChecker github.com/cloudtrust/keycloak-bridge/pkg/health ESHealthChecker
//go:generate mockgen -destination=./mock/flaki.go -package=mock -mock_names=FlakiHealthChecker=FlakiHealthChecker github.com/cloudtrust/common-healthcheck FlakiHealthChecker
//go:generate mockgen -destination=./mock/influx.go -package=mock -mock_names=InfluxHealthChecker=InfluxHealthChecker github.com/cloudtrust/common-healthcheck InfluxHealthChecker
//go:generate mockgen -destination=./mock/jaeger.go -package=mock -mock_names=JaegerHealthChecker=JaegerHealthChecker github.com/cloudtrust/common-healthcheck JaegerHealthChecker
//go:generate mockgen -destination=./mock/redis.go -package=mock -mock_names=RedisHealthChecker=RedisHealthChecker github.com/cloudtrust/common-healthcheck RedisHealthChecker
//go:generate mockgen -destination=./mock/sentry.go -package=mock -mock_names=SentryHealthChecker=SentryHealthChecker github.com/cloudtrust/common-healthcheck SentryHealthChecker
//go:generate mockgen -destination=./mock/keycloak.go -package=mock -mock_names=KeycloakHealthChecker=KeycloakHealthChecker github.com/cloudtrust/keycloak-bridge/pkg/health KeycloakHealthChecker
//go:generate mockgen -destination=./mock/storage.go -package=mock -mock_names=StoreModule=StoreModule github.com/cloudtrust/keycloak-bridge/pkg/health StoreModule

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	common "github.com/cloudtrust/common-healthcheck"
	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockESModule = mock.NewESHealthChecker(mockCtrl)
	var mockFlakiModule = mock.NewFlakiHealthChecker(mockCtrl)
	var mockInfluxModule = mock.NewInfluxHealthChecker(mockCtrl)
	var mockJaegerModule = mock.NewJaegerHealthChecker(mockCtrl)
	var mockRedisModule = mock.NewRedisHealthChecker(mockCtrl)
	var mockSentryModule = mock.NewSentryHealthChecker(mockCtrl)
	var mockKeycoakModule = mock.NewKeycloakHealthChecker(mockCtrl)
	var mockStorage = mock.NewStoreModule(mockCtrl)
	var m = map[string]time.Duration{
		"es":       1 * time.Minute,
		"flaki":    1 * time.Minute,
		"influx":   1 * time.Minute,
		"jaeger":   1 * time.Minute,
		"redis":    1 * time.Minute,
		"sentry":   1 * time.Minute,
		"keycloak": 1 * time.Minute,
	}

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule, mockFlakiModule, mockESModule, mockKeycoakModule, mockStorage, m)

	var (
		esReports       = []ESReport{{Name: "es", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		flakiReports    = []common.FlakiReport{{Name: "flaki", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		influxReports   = []common.InfluxReport{{Name: "influx", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		jaegerReports   = []common.JaegerReport{{Name: "jaeger", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		redisReports    = []common.RedisReport{{Name: "redis", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		sentryReports   = []common.SentryReport{{Name: "sentry", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		keycloakReports = []KeycloakReport{{Name: "keycloak", Duration: time.Duration(1 * time.Second), Status: common.OK}}

		makeStoredReport = func(name string) StoredReport {
			return StoredReport{
				ComponentID:     "000-000-000-00",
				ComponentName:   "flaki",
				HealthcheckUnit: name,
				Reports:         json.RawMessage(`[{"name":"XXX", "status":"OK", "duration":"1s"}]`),
				LastUpdated:     time.Now(),
				ValidUntil:      time.Now().Add(1 * time.Hour),
			}
		}
	)

	// ES.
	mockESModule.EXPECT().HealthChecks(context.Background()).Return(esReports).Times(1)
	mockStorage.EXPECT().Update("es", m["es"], gomock.Any()).Times(1)
	{
		var report = c.ExecESHealthChecks(context.Background())
		assert.Equal(t, `[{"name":"es","duration":"1s","status":"OK","error":""}]`, string(report))
	}

	// Flaki.
	mockFlakiModule.EXPECT().HealthChecks(context.Background()).Return(flakiReports).Times(1)
	mockStorage.EXPECT().Update("flaki", m["flaki"], gomock.Any()).Times(1)
	{
		var report = c.ExecFlakiHealthChecks(context.Background())
		//	var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"flaki","duration":"1s","status":"OK","error":""}]`, string(report))
	}

	// Influx.
	mockInfluxModule.EXPECT().HealthChecks(context.Background()).Return(influxReports).Times(1)
	mockStorage.EXPECT().Update("influx", m["influx"], gomock.Any()).Times(1)
	{
		var report = c.ExecInfluxHealthChecks(context.Background())
		//	var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"influx","duration":"1s","status":"OK","error":""}]`, string(report))
	}

	// Jaeger.
	mockJaegerModule.EXPECT().HealthChecks(context.Background()).Return(jaegerReports).Times(1)
	mockStorage.EXPECT().Update("jaeger", m["jaeger"], gomock.Any()).Times(1)
	{
		var report = c.ExecJaegerHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"jaeger","duration":"1s","status":"OK","error":""}]`, string(json))
	}

	// Redis.
	mockRedisModule.EXPECT().HealthChecks(context.Background()).Return(redisReports).Times(1)
	mockStorage.EXPECT().Update("redis", m["redis"], gomock.Any()).Times(1)
	{
		var report = c.ExecRedisHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"redis","duration":"1s","status":"OK","error":""}]`, string(json))
	}

	// Sentry.
	mockSentryModule.EXPECT().HealthChecks(context.Background()).Return(sentryReports).Times(1)
	mockStorage.EXPECT().Update("sentry", m["sentry"], gomock.Any()).Times(1)
	{
		var report = c.ExecSentryHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"sentry","duration":"1s","status":"OK","error":""}]`, string(json))
	}

	// Keycloak.
	mockKeycoakModule.EXPECT().HealthChecks(context.Background()).Return(keycloakReports).Times(1)
	mockStorage.EXPECT().Update("keycloak", m["keycloak"], gomock.Any()).Times(1)
	{
		var report = c.ExecKeycloakHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"keycloak","duration":"1s","status":"OK","error":""}]`, string(json))
	}

	// All.
	mockStorage.EXPECT().Read("es").Return(makeStoredReport("es"), nil).Times(1)
	mockStorage.EXPECT().Read("flaki").Return(makeStoredReport("flaki"), nil).Times(1)
	mockStorage.EXPECT().Read("influx").Return(makeStoredReport("influx"), nil).Times(1)
	mockStorage.EXPECT().Read("jaeger").Return(makeStoredReport("jaeger"), nil).Times(1)
	mockStorage.EXPECT().Read("redis").Return(makeStoredReport("redis"), nil).Times(1)
	mockStorage.EXPECT().Read("sentry").Return(makeStoredReport("sentry"), nil).Times(1)
	mockStorage.EXPECT().Read("keycloak").Return(makeStoredReport("keycloak"), nil).Times(1)
	{
		var report = c.AllHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, "{\"es\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"flaki\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"influx\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"jaeger\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"keycloak\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"redis\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}],\"sentry\":[{\"name\":\"XXX\",\"status\":\"OK\",\"duration\":\"1s\"}]}", string(json))
	}
}

func TestHealthChecksFail(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockESModule = mock.NewESHealthChecker(mockCtrl)
	var mockFlakiModule = mock.NewFlakiHealthChecker(mockCtrl)
	var mockInfluxModule = mock.NewInfluxHealthChecker(mockCtrl)
	var mockJaegerModule = mock.NewJaegerHealthChecker(mockCtrl)
	var mockRedisModule = mock.NewRedisHealthChecker(mockCtrl)
	var mockSentryModule = mock.NewSentryHealthChecker(mockCtrl)
	var mockKeycoakModule = mock.NewKeycloakHealthChecker(mockCtrl)
	var mockStorage = mock.NewStoreModule(mockCtrl)
	var m = map[string]time.Duration{
		"es":       1 * time.Minute,
		"flaki":    1 * time.Minute,
		"influx":   1 * time.Minute,
		"jaeger":   1 * time.Minute,
		"redis":    1 * time.Minute,
		"sentry":   1 * time.Minute,
		"keycloak": 1 * time.Minute,
	}

	var c = NewComponent(mockInfluxModule, mockJaegerModule, mockRedisModule, mockSentryModule, mockFlakiModule, mockESModule, mockKeycoakModule, mockStorage, m)

	var (
		esReports       = []ESReport{{Name: "es", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		flakiReports    = []common.FlakiReport{{Name: "flaki", Duration: time.Duration(1 * time.Second), Status: common.OK}}
		influxReports   = []common.InfluxReport{{Name: "influx", Duration: time.Duration(1 * time.Second), Status: common.Deactivated}}
		jaegerReports   = []common.JaegerReport{{Name: "jaeger", Duration: time.Duration(1 * time.Second), Status: common.KO, Error: fmt.Errorf("fail")}}
		redisReports    = []common.RedisReport{{Name: "redis", Duration: time.Duration(1 * time.Second), Status: common.Degraded, Error: fmt.Errorf("fail")}}
		sentryReports   = []common.SentryReport{{Name: "sentry", Duration: time.Duration(1 * time.Second), Status: common.KO, Error: fmt.Errorf("fail")}}
		keycloakReports = []KeycloakReport{{Name: "keycloak", Duration: time.Duration(1 * time.Second), Status: common.KO, Error: fmt.Errorf("fail")}}

		makeStoredReport = func(name string) StoredReport {
			return StoredReport{
				ComponentID:     "000-000-000-00",
				ComponentName:   "flaki",
				HealthcheckUnit: name,
				Reports:         json.RawMessage(`[{"name":"XXX", "status":"OK", "duration":"1s"}]`),
				LastUpdated:     time.Now(),
				ValidUntil:      time.Now().Add(1 * time.Hour),
			}
		}
	)

	// ES.
	mockESModule.EXPECT().HealthChecks(context.Background()).Return(esReports).Times(1)
	mockStorage.EXPECT().Update("es", m["es"], gomock.Any()).Times(1)
	{
		var report = c.ExecESHealthChecks(context.Background())
		assert.Equal(t, `[{"name":"es","duration":"1s","status":"OK","error":""}]`, string(report))
	}

	// Flaki.
	mockFlakiModule.EXPECT().HealthChecks(context.Background()).Return(flakiReports).Times(1)
	mockStorage.EXPECT().Update("flaki", m["flaki"], gomock.Any()).Times(1)
	{
		var report = c.ExecFlakiHealthChecks(context.Background())
		assert.Equal(t, `[{"name":"flaki","duration":"1s","status":"OK","error":""}]`, string(report))
	}

	// Influx.
	mockInfluxModule.EXPECT().HealthChecks(context.Background()).Return(influxReports).Times(1)
	mockStorage.EXPECT().Update("influx", m["influx"], gomock.Any()).Times(1)
	{
		var report = c.ExecInfluxHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"influx","duration":"1s","status":"Deactivated","error":""}]`, string(json))
	}

	// Jaeger.
	mockJaegerModule.EXPECT().HealthChecks(context.Background()).Return(jaegerReports).Times(1)
	mockStorage.EXPECT().Update("jaeger", m["jaeger"], gomock.Any()).Times(1)
	{
		var report = c.ExecJaegerHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"jaeger","duration":"1s","status":"KO","error":"fail"}]`, string(json))
	}

	// Redis.
	mockRedisModule.EXPECT().HealthChecks(context.Background()).Return(redisReports).Times(1)
	mockStorage.EXPECT().Update("redis", m["redis"], gomock.Any()).Times(1)
	{
		var report = c.ExecRedisHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"redis","duration":"1s","status":"Degraded","error":"fail"}]`, string(json))
	}

	// Sentry.
	mockSentryModule.EXPECT().HealthChecks(context.Background()).Return(sentryReports).Times(1)
	mockStorage.EXPECT().Update("sentry", m["sentry"], gomock.Any()).Times(1)
	{
		var report = c.ExecSentryHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"sentry","duration":"1s","status":"KO","error":"fail"}]`, string(json))
	}

	// Keycloak.
	mockKeycoakModule.EXPECT().HealthChecks(context.Background()).Return(keycloakReports).Times(1)
	mockStorage.EXPECT().Update("keycloak", m["keycloak"], gomock.Any()).Times(1)
	{
		var report = c.ExecKeycloakHealthChecks(context.Background())
		var json, _ = json.Marshal(&report)
		assert.Equal(t, `[{"name":"keycloak","duration":"1s","status":"KO","error":"fail"}]`, string(json))
	}

	// All.
	mockStorage.EXPECT().Read("es").Return(makeStoredReport("es"), nil).Times(1)
	mockStorage.EXPECT().Read("flaki").Return(makeStoredReport("flaki"), nil).Times(1)
	mockStorage.EXPECT().Read("influx").Return(makeStoredReport("influx"), nil).Times(1)
	mockStorage.EXPECT().Read("jaeger").Return(makeStoredReport("jaeger"), nil).Times(1)
	mockStorage.EXPECT().Read("redis").Return(makeStoredReport("redis"), nil).Times(1)
	mockStorage.EXPECT().Read("sentry").Return(makeStoredReport("sentry"), nil).Times(1)
	mockStorage.EXPECT().Read("keycloak").Return(makeStoredReport("keycloak"), nil).Times(1)
	{
		var reply = c.AllHealthChecks(context.Background())
		var m map[string]json.RawMessage
		json.Unmarshal(reply, &m)

		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["es"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["flaki"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["influx"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["jaeger"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["redis"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["sentry"]))
		assert.Equal(t, `[{"name":"XXX","status":"OK","duration":"1s"}]`, string(m["keycloak"]))
	}
}
