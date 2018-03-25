package keycloakd

import (
	"testing"
	"time"

	"github.com/cloudtrust/keycloak-bridge/internal/keycloakd/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMetrics(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInflux = mock.NewInflux(mockCtrl)
	var mockMetrics = mock.NewGoKitMetrics(mockCtrl)

	var influxMetrics = NewMetrics(mockInflux, mockMetrics)

	mockMetrics.EXPECT().NewCounter("counter name").Return(nil).Times(1)
	influxMetrics.NewCounter("counter name")

	mockMetrics.EXPECT().NewGauge("gauge name").Return(nil).Times(1)
	influxMetrics.NewGauge("gauge name")

	mockMetrics.EXPECT().NewHistogram("histogram name").Return(nil).Times(1)
	influxMetrics.NewHistogram("histogram name")

	mockMetrics.EXPECT().WriteLoop(gomock.Any(), mockInflux).Return().Times(1)
	influxMetrics.WriteLoop(make(chan time.Time))

	mockInflux.EXPECT().Ping(1*time.Second).Return(time.Duration(0), "", nil).Times(1)
	influxMetrics.Ping(1 * time.Second)

	mockInflux.EXPECT().Write(nil).Return(nil).Times(1)
	influxMetrics.Write(nil)
}

func TestNoopMetrics(t *testing.T) {
	var noopMetrics = &NoopMetrics{}

	assert.Nil(t, noopMetrics.Write(nil))

	var counter = noopMetrics.NewCounter("counter name")
	assert.IsType(t, &NoopCounter{}, counter)
	assert.IsType(t, &NoopCounter{}, counter.With())

	var gauge = noopMetrics.NewGauge("gauge name")
	assert.IsType(t, &NoopGauge{}, gauge)
	assert.IsType(t, &NoopGauge{}, gauge.With())

	var histogram = noopMetrics.NewHistogram("histogram name")
	assert.IsType(t, &NoopHistogram{}, histogram)
	assert.IsType(t, &NoopHistogram{}, histogram.With())

	var duration, s, err = noopMetrics.Ping(1 * time.Second)
	assert.Equal(t, time.Duration(0), duration)
	assert.Equal(t, "", s)
	assert.Nil(t, err)
}
