package health_test

//go:generate mockgen -destination=./mock/influx.go -package=mock -mock_names=InfluxModule=InfluxModule,Influx=Influx  github.com/cloudtrust/keycloak-bridge/pkg/health InfluxModule,Influx

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestInfluxHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInflux = mock.NewInflux(mockCtrl)

	var m = NewInfluxModule(mockInflux, true)

	// HealthChecks.
	{
		mockInflux.EXPECT().Ping(5*time.Second).Return(1*time.Second, "", nil).Times(1)
		var report = m.HealthChecks(context.Background())[0]
		assert.Equal(t, "ping", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// HealthChecks error.
	{
		mockInflux.EXPECT().Ping(5*time.Second).Return(0*time.Second, "", fmt.Errorf("fail")).Times(1)
		var report = m.HealthChecks(context.Background())[0]
		assert.Equal(t, "ping", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, KO, report.Status)
		assert.NotZero(t, report.Error)
	}
}

func TestNoopInfluxHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockInflux = mock.NewInflux(mockCtrl)

	var m = NewInfluxModule(mockInflux, false)

	// HealthChecks.
	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "ping", report.Name)
	assert.Equal(t, "N/A", report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)
}
