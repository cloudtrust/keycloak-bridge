package statistics

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetActionsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetActionsEndpoint(mockComponent)

	var ctx = context.Background()

	mockComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
	var res, err = e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = prmRealm

	mockComponent.EXPECT().GetStatistics(ctx, prmRealm).Return(api.StatisticsRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsIdentificationsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetStatisticsIdentificationsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)
	req[prmRealm] = prmRealm

	mockComponent.EXPECT().GetStatisticsIdentifications(ctx, prmRealm).Return(api.IdentificationStatisticsRepresentation{}, nil)
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
	req[prmRealm] = "realm"

	mockComponent.EXPECT().GetStatisticsUsers(ctx, "realm").Return(api.StatisticsUsersRepresentation{}, nil)
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
	req[prmRealm] = "realm"

	mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, "realm").Return(map[string]int64{}, nil)
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
	req[prmRealm] = "realm"
	req[prmQryUnit] = "hours"

	mockComponent.EXPECT().GetStatisticsAuthentications(ctx, prmRealm, "hours", nil).Return([][]int64{}, nil)
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
	req[prmRealm] = prmRealm
	req[prmQryMax] = "6"

	mockComponent.EXPECT().GetStatisticsAuthenticationsLog(ctx, "realm", "6").Return([]api.StatisticsConnectionRepresentation{}, nil)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
