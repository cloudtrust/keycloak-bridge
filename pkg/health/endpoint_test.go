package health

import (
	"context"
	"testing"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthCheckEndpoint(t *testing.T) {
	var mockComponent = &mockComponent{fail: false}

	var e = MakeInfluxHealthCheckEndpoint(mockComponent)

	// Health success.
	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "influx", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.fail = true
	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "influx", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}

func TestJaegerHealthCheckEndpoint(t *testing.T) {
	var mockComponent = &mockComponent{fail: false}

	var e = MakeJaegerHealthCheckEndpoint(mockComponent)

	// Health success.
	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "jaeger", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.fail = true
	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "jaeger", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}

func TestRedisHealthCheckEndpoint(t *testing.T) {
	var mockComponent = &mockComponent{fail: false}

	var e = MakeRedisHealthCheckEndpoint(mockComponent)

	// Health success.
	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "redis", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.fail = true
	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "redis", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}
func TestSentryHealthCheckEndpoint(t *testing.T) {
	var mockComponent = &mockComponent{fail: false}

	var e = MakeSentryHealthCheckEndpoint(mockComponent)

	// Health success.
	var r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	var hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "sentry", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, OK, hr.Status)
	assert.Zero(t, hr.Error)

	// Health error.
	mockComponent.fail = true
	r, err = e(context.Background(), nil)
	assert.Nil(t, err)
	hr = r.(HealthReports).Reports[0]
	assert.Equal(t, "sentry", hr.Name)
	assert.NotZero(t, hr.Duration)
	assert.Equal(t, KO, hr.Status)
	assert.Equal(t, "fail", hr.Error)
}

func MakeMockHealthEndpoint(name string, fail bool) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		var r = HealthReport{
			Name:     name,
			Duration: time.Duration(1 * time.Second).String(),
			Status:   OK,
			Error:    "",
		}
		if fail {
			r.Status = KO
			r.Error = "fail"
		}
		return HealthReports{Reports: []HealthReport{r}}, nil
	}
}
