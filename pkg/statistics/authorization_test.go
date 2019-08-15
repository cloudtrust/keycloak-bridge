package statistics

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	WithoutAuthorization = `{}`
	WithAuthorization    = `{
		"master": { 
			"toe": {
				"ST_GetStatistics": {"*": {"*": {} }}
			}
		}
	}`
)

func testAuthorization(t *testing.T, jsonAuthz string, tester func(Component, *mock.Component, context.Context, map[string]string)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()

	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, mockLogger, jsonAuthz)
	assert.Nil(t, err)

	mockComponent := mock.NewComponent(mockCtrl)

	var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockComponent)

	var accessToken = "TOKEN=="
	var groups = []string{"toe"}
	var realmName = "master"
	var userID = "123-456-789"
	var groupName = "titi"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

	mp := make(map[string]string)
	mp["realm"] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockComponent, ctx, mp)
}

func TestGetStatisticsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatistics(ctx, mp["realm"]).Return(api.StatisticsRepresentation{}, nil).Times(1)
		_, err := auth.GetStatistics(ctx, mp["realm"])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatistics(ctx, mp["realm"])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
