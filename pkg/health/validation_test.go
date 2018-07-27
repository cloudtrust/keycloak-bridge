package health_test

import (
	"context"
	"encoding/json"
	"testing"

	. "github.com/cloudtrust/keycloak-bridge/pkg/health"
	"github.com/cloudtrust/keycloak-bridge/pkg/health/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestValidationMW(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockHealthCheckers = mock.NewHealthCheckers(mockCtrl)

	var (
		validValues = map[string]struct{}{
			"cockroach": struct{}{},
			"influx":    struct{}{},
			"jaeger":    struct{}{},
		}
		m   = MakeValidationMiddleware(validValues)(mockHealthCheckers)
		rep = json.RawMessage(`{"key":"value"}`)
	)

	var tsts = []struct {
		name    string
		isValid bool
	}{
		{"cockroach", true},
		{"influx", true},
		{"jaeger", true},
		{"unkown", false},
		{"notvalid", false},
	}

	for _, tst := range tsts {
		var req = map[string]string{
			"module": tst.name,
		}

		if tst.isValid {
			mockHealthCheckers.EXPECT().HealthChecks(context.Background(), req).Return(rep, nil).Times(1)
		}

		var report, err = m.HealthChecks(context.Background(), req)

		if tst.isValid {
			assert.Nil(t, err)
			assert.NotNil(t, report)
		} else {
			assert.IsType(t, &ErrUnknownHCModule{}, err)
			assert.Contains(t, err.Error(), tst.name)
			assert.Nil(t, report)
		}
	}
}
