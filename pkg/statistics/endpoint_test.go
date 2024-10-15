package statistics

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestMakeGetActionsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockComponent := mock.NewComponent(mockCtrl)

	e := MakeGetActionsEndpoint(mockComponent)

	ctx := context.Background()

	mockComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
	res, err := e(ctx, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsIdentificationsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockComponent := mock.NewComponent(mockCtrl)

	e := MakeGetStatisticsIdentificationsEndpoint(mockComponent)

	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = prmRealm

	mockComponent.EXPECT().GetStatisticsIdentifications(ctx, prmRealm).Return(api.IdentificationStatisticsRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsUsersEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockComponent := mock.NewComponent(mockCtrl)

	e := MakeGetStatisticsUsersEndpoint(mockComponent)

	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = "realm"

	mockComponent.EXPECT().GetStatisticsUsers(ctx, "realm").Return(api.StatisticsUsersRepresentation{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetStatisticsAuthenticatorsEndpoint(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockComponent := mock.NewComponent(mockCtrl)

	e := MakeGetStatisticsAuthenticatorsEndpoint(mockComponent)

	ctx := context.Background()
	req := make(map[string]string)
	req[prmRealm] = "realm"

	mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, "realm").Return(map[string]int64{}, nil)
	res, err := e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
