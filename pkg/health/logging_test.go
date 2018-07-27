package health_test

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger

import (
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"testing"
	"time"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func TestEndpointLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewHealthCheckers(mockCtrl)

	var m = MakeEndpointLoggingMW(mockLogger)(MakeHealthChecksEndpoint(mockComponent))

	var (
		req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}
		corrID = strconv.FormatUint(rand.Uint64(), 10)
		ctx    = context.WithValue(context.Background(), "correlation_id", corrID)
		report = json.RawMessage(`{"key":"value"}`)
	)

	// With correlation ID.
	mockLogger.EXPECT().Log("correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	mockComponent.EXPECT().HealthChecks(ctx, req).Return(report, nil).Times(1)
	m(ctx, req)

	// Without correlation ID.
	mockComponent.EXPECT().HealthChecks(context.Background(), req).Return(report, nil).Times(1)
	var f = func() {
		m(context.Background(), req)
	}
	assert.Panics(t, f)
}

func TestComponentLoggingMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = mock.NewLogger(mockCtrl)
	var mockComponent = mock.NewHealthCheckers(mockCtrl)

	var m = MakeComponentLoggingMW(mockLogger)(mockComponent)

	var (
		req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}
		corrID = strconv.FormatUint(rand.Uint64(), 10)
		ctx    = context.WithValue(context.Background(), "correlation_id", corrID)
		report = json.RawMessage(`{"key":"value"}`)
	)

	// With correlation ID.
	mockLogger.EXPECT().Log("request", req, "correlation_id", corrID, "took", gomock.Any()).Return(nil).Times(1)
	mockComponent.EXPECT().HealthChecks(ctx, req).Return(report, nil).Times(1)
	m.HealthChecks(ctx, req)

	// Without correlation ID.
	mockComponent.EXPECT().HealthChecks(context.Background(), req).Return(report, nil).Times(1)
	var f = func() {
		m.HealthChecks(context.Background(), req)
	}
	assert.Panics(t, f)
}
