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

func TestInfluxHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeInfluxHealthCheckEndpoint(mockComponent)

	// Health success.
	mockComponent.EXPECT().InfluxHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "influx", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "influx", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.EXPECT().InfluxHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "influx", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)

	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "influx", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}

func TestJaegerHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeJaegerHealthCheckEndpoint(mockComponent)

	// Health success.
	mockComponent.EXPECT().JaegerHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "jaeger", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.EXPECT().JaegerHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "jaeger", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)

	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "jaeger", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}

func TestRedisHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeRedisHealthCheckEndpoint(mockComponent)

	// Health success.
	mockComponent.EXPECT().RedisHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "redis", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "redis", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.EXPECT().RedisHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "redis", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)

	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "redis", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}
func TestSentryHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeSentryHealthCheckEndpoint(mockComponent)

	// Health success.
	mockComponent.EXPECT().SentryHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "sentry", Duration: (1 * time.Second).String(), Status: OK}}}).Times(1)

	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "sentry", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.EXPECT().SentryHealthChecks(context.Background()).Return(HealthReports{Reports: []HealthReport{{Name: "sentry", Duration: (1 * time.Second).String(), Status: KO, Error: "fail"}}}).Times(1)

	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "sentry", hr.Name)
	assert.Equal(t, (1 * time.Second).String(), hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}
