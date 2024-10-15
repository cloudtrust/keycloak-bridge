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
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

var WithoutAuthorization = []configuration.Authorization{}

func WithAuthorization() []configuration.Authorization {
	realmName := "master"
	toe := "toe"
	any := "*"

	authorizations := []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.StatisticAPI) {
		action := string(action.Name)
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
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockLogger := log.NewNopLogger()

	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	mockAuthorizationDBReader := mock.NewAuthorizationDBReader(mockCtrl)
	mockAuthorizationDBReader.EXPECT().GetAuthorizations(gomock.Any()).Return(authz, nil)

	authorizations, err := security.NewAuthorizationManager(mockAuthorizationDBReader, mockKeycloakClient, mockLogger)
	assert.Nil(t, err)

	mockComponent := mock.NewComponent(mockCtrl)

	authorizationMW := MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockComponent)

	accessToken := "TOKEN=="
	groups := []string{"toe"}
	realmName := "master"
	userID := "123-456-789"
	groupName := "titi"

	ctx := context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
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
