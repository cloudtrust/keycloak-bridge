package statistics

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/statistics"
	"github.com/cloudtrust/keycloak-bridge/pkg/statistics/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestGetActionsString(t *testing.T) {
	assert.Len(t, GetActions(), len(actions))
}

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
	mp[prmRealm] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(ctx, accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockComponent, ctx, mp)
}

func TestGetActionsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil)
		_, err := auth.GetActions(ctx)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatistics(ctx, mp[prmRealm]).Return(api.StatisticsRepresentation{}, nil)
		_, err := auth.GetStatistics(ctx, mp[prmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsIdentificationsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsIdentifications(ctx, mp[prmRealm]).Return(api.IdentificationStatisticsRepresentation{}, nil)
		_, err := auth.GetStatisticsIdentifications(ctx, mp[prmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsUsersAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsUsers(ctx, mp[prmRealm]).Return(api.StatisticsUsersRepresentation{}, nil)
		_, err := auth.GetStatisticsUsers(ctx, mp[prmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticatorsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticators(ctx, mp[prmRealm]).Return(map[string]int64{}, nil)
		_, err := auth.GetStatisticsAuthenticators(ctx, mp[prmRealm])
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthentications(ctx, mp[prmRealm], mp[prmQryUnit], nil).Return([][]int64{}, nil)
		_, err := auth.GetStatisticsAuthentications(ctx, mp[prmRealm], mp[prmQryUnit], nil)
		assert.Nil(t, err)
	})
}

func TestGetStatisticsAuthenticationsLogAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetStatisticsAuthenticationsLog(ctx, mp[prmRealm], mp[prmQryMax]).Return([]api.StatisticsConnectionRepresentation{}, nil)
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp[prmRealm], mp[prmQryMax])
		assert.Nil(t, err)
	})
}

func TestGetMigrationReportAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetMigrationReport(ctx, mp[prmRealm]).Return(map[string]bool{}, nil)
		_, err := auth.GetMigrationReport(ctx, mp[prmRealm])
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
		_, err := auth.GetStatistics(ctx, mp[prmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsIdentificationsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsIdentifications(ctx, mp[prmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsUsersDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsUsers(ctx, mp[prmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthentications(ctx, mp[prmRealm], mp[prmQryUnit], nil)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticationsLogDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticationsLog(ctx, mp[prmRealm], mp[prmQryMax])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetStatisticsAuthenticatorsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetStatisticsAuthenticators(ctx, mp[prmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetMigrationReportDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetMigrationReport(ctx, mp[prmRealm])
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
