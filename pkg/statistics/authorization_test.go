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
				"ST_GetActions": {"*": {}},
				"ST_GetStatistics": {"*": {"*": {} }},
				"ST_GetStatisticsUsers": {"*": {"*": {} }},
				"ST_GetStatisticsAuthenticators": {"*": {"*": {} }},
				"ST_GetStatisticsAuthentications": {"*": {"*": {} }},
				"ST_GetStatisticsAuthenticationsLog": {"*": {"*": {} }}
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

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(ctx, accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockComponent, ctx, mp)
}

func TestGetActionsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetActions(ctx).Return([]string{}, nil).Times(1)
		_, err := auth.GetActions(ctx)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatistics(ctx, mp["realm"]).Return(api.StatisticsRepresentation{}, nil).Times(1)
		_, err := auth.GetStatistics(ctx, mp["realm"])
		assert.Nil(t, err)
	})
}
func TestGetStatisticsUsersAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsUsers(ctx, mp["realm"]).Return(api.StatisticsUsersRepresentation{}, nil).Times(1)
		_, err := auth.GetStatisticsUsers(ctx, mp["realm"])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticatorsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, mp["realm"]).Return(map[string]int64{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthenticators(ctx, mp["realm"])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthentications(ctx, mp["realm"], mp["unit"], nil).Return([][]int64{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthentications(ctx, mp["realm"], mp["unit"], nil)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsLogAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticationsLog(ctx, mp["realm"], mp["max"]).Return([]api.StatisticsConnectionRepresentation{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp["realm"], mp["max"])
		assert.Nil(t, err)
	})
}

func TestGetActionsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetActions(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatistics(ctx, mp["realm"])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsUsersDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsUsers(ctx, mp["realm"])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthentications(ctx, mp["realm"], mp["unit"], nil)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsLogDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp["realm"], mp["max"])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticatorsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticators(ctx, mp["realm"])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
