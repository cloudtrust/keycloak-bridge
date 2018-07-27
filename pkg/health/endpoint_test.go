package health_test

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=HealthCheckers=HealthCheckers github.com/cloudtrust/keycloak-bridge/pkg/health HealthCheckers

import (
	"context"
	"encoding/json"
	"math/rand"
	"strconv"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheckEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockComponent = mock.NewHealthCheckers(mockCtrl)

	var e = MakeHealthChecksEndpoint(mockComponent)

	var (
		req = map[string]string{
			"module":      "cockroach",
			"healthcheck": "ping",
			"nocache":     "1",
		}
		corrID          = strconv.FormatUint(rand.Uint64(), 10)
		ctx             = context.WithValue(context.Background(), "correlation_id", corrID)
		cockroachReport = reportIndent(json.RawMessage(`[{"name": "ping cockroach","status": "OK","duration": "1ms"}]`))
	)

	mockComponent.EXPECT().HealthChecks(ctx, req).Return(cockroachReport, nil).Times(1)
	{
		var reports, err = e(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, cockroachReport, reports)
	}
}
