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
	req["realm"] = "realm"

	mockComponent.EXPECT().GetStatistics(ctx, "realm").Return(api.StatisticsRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsUsersEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsUsersEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = "realm"

	mockComponent.EXPECT().GetStatisticsUsers(ctx, "realm").Return(api.StatisticsUsersRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsAuthenticatorsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsAuthenticatorsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = "realm"

	mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, "realm").Return(map[string]int64{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsAuthenticationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsAuthenticationsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = "realm"
	req["unit"] = "hours"

	mockComponent.EXPECT().GetStatisticsAuthentications(ctx, "realm", "hours", nil).Return([][]int64{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsAuthenticationsLogEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsAuthenticationsLogEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req["realm"] = "realm"
	req["max"] = "6"

	mockComponent.EXPECT().GetStatisticsAuthenticationsLog(ctx, "realm", "6").Return([]api.StatisticsConnectionRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
