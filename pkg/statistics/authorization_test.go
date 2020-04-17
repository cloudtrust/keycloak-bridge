package statistics

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/configuration"
	"github.com/cloudtrust/common-service/log"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

var (
	WithoutAuthorization = []configuration.Authorization{}
)

func WithAuthorization() []configuration.Authorization {
	var realmName = "master"
	var toe = "toe"
	var any = "*"

	var authorizations = []configuration.Authorization{}
	for _, action := range actions {
		var action = string(action.Name)
		authorizations = append(authorizations, configuration.Authorization{
			RealmID:         &realmName,
			GroupName:       &toe,
			Action:          &action,
			TargetRealmID:   &any,
			TargetGroupName: &any,
		})
	}

	return authorizations
}

func testAuthorization(t *testing.T, authz []configuration.Authorization, tester func(Component, *mock.Component, context.Context, map[string]string)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()

	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	var mockAuthorizationDBReader = mock.NewAuthorizationDBReader(mockCtrl)
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authz, nil)

	var authorizations, err = security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
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
	mp[PrmRealm] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(ctx, accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockComponent, ctx, mp)
}

func TestGetActionsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil).Times(1)
		_, err := auth.GetActions(ctx)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatistics(ctx, mp[PrmRealm]).Return(api.StatisticsRepresentation{}, nil).Times(1)
		_, err := auth.GetStatistics(ctx, mp[PrmRealm])
		assert.Nil(t, err)
	})
}
func TestGetStatisticsUsersAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsUsers(ctx, mp[PrmRealm]).Return(api.StatisticsUsersRepresentation{}, nil).Times(1)
		_, err := auth.GetStatisticsUsers(ctx, mp[PrmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticatorsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, mp[PrmRealm]).Return(map[string]int64{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthenticators(ctx, mp[PrmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthentications(ctx, mp[PrmRealm], mp[PrmQryUnit], nil).Return([][]int64{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthentications(ctx, mp[PrmRealm], mp[PrmQryUnit], nil)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsLogAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticationsLog(ctx, mp[PrmRealm], mp[PrmQryMax]).Return([]api.StatisticsConnectionRepresentation{}, nil).Times(1)
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp[PrmRealm], mp[PrmQryMax])
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
		_, err := auth.GetStatistics(ctx, mp[PrmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsUsersDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsUsers(ctx, mp[PrmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthentications(ctx, mp[PrmRealm], mp[PrmQryUnit], nil)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsLogDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp[PrmRealm], mp[PrmQryMax])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticatorsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticators(ctx, mp[PrmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
