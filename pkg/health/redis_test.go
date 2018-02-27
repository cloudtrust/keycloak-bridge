package health_test

import (
	"context"
	"fmt"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestRedisHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockRedis = mock.NewRedis(mockCtrl)

	mockRedis.EXPECT().Do("PING").Return(nil, nil).Times(1)

	var m = NewRedisModule(mockRedis)

	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, OK, report.Status)
	assert.Zero(t, report.Error)

	// Redis fail.
	mockRedis.EXPECT().Do("PING").Return(nil, fmt.Errorf("fail")).Times(1)
	report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, KO, report.Status)
	assert.NotZero(t, report.Error)
}
func TestNoopRedisHealthChecks(t *testing.T) {
	var m = NewRedisModule(nil)

	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "ping", report.Name)
	assert.NotZero(t, report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)
}
