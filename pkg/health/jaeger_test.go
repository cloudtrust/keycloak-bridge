package health_test

//go:generate mockgen -destination=./mock/jaeger.go -package=mock -mock_names=JaegerModule=JaegerModule,SystemDConn=SystemDConn  github.com/cloudtrust/keycloak-bridge/pkg/health JaegerModule,SystemDConn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/coreos/go-systemd/dbus"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestJaegerHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockSystemDConn = mock.NewSystemDConn(mockCtrl)

	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	var m = NewJaegerModule(mockSystemDConn, s.Client(), s.URL[7:], true)

	var units = []dbus.UnitStatus{{Name: "agent.service", ActiveState: "active"}}

	// HealthChecks
	{
		mockSystemDConn.EXPECT().ListUnitsByNames([]string{"agent.service"}).Return(units, nil).Times(1)
		var report = m.HealthChecks(context.Background())[0]
		assert.Equal(t, "jaeger agent systemd unit check", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, OK, report.Status)
		assert.Zero(t, report.Error)
	}

	// SystemD fail.
	{
		mockSystemDConn.EXPECT().ListUnitsByNames([]string{"agent.service"}).Return(nil, fmt.Errorf("fail")).Times(1)
		var report = m.HealthChecks(context.Background())[0]
		assert.Equal(t, "jaeger agent systemd unit check", report.Name)
		assert.NotZero(t, report.Duration)
		assert.Equal(t, KO, report.Status)
		assert.NotZero(t, report.Error)
	}
}

func TestNoopJaegerHealthChecks(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockSystemDConn = mock.NewSystemDConn(mockCtrl)

	var s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()

	var m = NewJaegerModule(mockSystemDConn, s.Client(), "jaeger-collector:14269", false)

	var report = m.HealthChecks(context.Background())[0]
	assert.Equal(t, "jaeger agent systemd unit check", report.Name)
	assert.Equal(t, "N/A", report.Duration)
	assert.Equal(t, Deactivated, report.Status)
	assert.Zero(t, report.Error)
}
