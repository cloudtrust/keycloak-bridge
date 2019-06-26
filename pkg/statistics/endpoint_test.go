package statistics

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetStatisticsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockComponent.EXPECT().GetStatistics(ctx, req).Return(api.StatisticsRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
