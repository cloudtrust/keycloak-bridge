package events

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service/v2"
	"github.com/cloudtrust/common-service/v2/configuration"
	"github.com/cloudtrust/common-service/v2/log"
	"github.com/cloudtrust/common-service/v2/security"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
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
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.EventsAPI) {
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

func PartialAuthorization() []configuration.Authorization {
	var realmName = "master"
	var toe = "toe"
	var any = "*"

	var authorizations = []configuration.Authorization{}
	for _, action := range security.Actions.GetActionsForAPIs(security.BridgeService, security.EventsAPI) {
		var action = string(action.Name)
		authorizations = append(authorizations, configuration.Authorization{
			RealmID:         &realmName,
			GroupName:       &toe,
			Action:          &action,
			TargetRealmID:   &realmName,
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

	mockEventsComponent := mock.NewComponent(mockCtrl)

	var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockEventsComponent)

	var accessToken = "TOKEN=="
	var groups = []string{"toe"}
	var realmName = "master"
	var userID = "123-456-789"
	var groupName = "titi"

	var ctx = context.WithValue(context.Background(), cs.CtContextAccessToken, accessToken)
	ctx = context.WithValue(ctx, cs.CtContextGroups, groups)
	ctx = context.WithValue(ctx, cs.CtContextRealm, realmName)

	mp := make(map[string]string)
	mp[prmPathRealm] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(ctx, accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockEventsComponent, ctx, mp)
}

func TestGetActionsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetActions(ctx).Return([]api.ActionRepresentation{}, nil).Times(1)
		_, err := auth.GetActions(ctx)
		assert.Nil(t, err)
	})
}

func TestGetEventsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEvents(ctx, mp).Return(api.AuditEventsRepresentation{}, nil).Times(1)
		_, err := auth.GetEvents(ctx, mp)
		assert.Nil(t, err)
	})

	testAuthorization(t, PartialAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEvents(ctx, mp).Return(api.AuditEventsRepresentation{}, nil).Times(1)
		_, err := auth.GetEvents(ctx, mp)
		assert.Nil(t, err)
	})
}

func TestGetEventsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetEvents(ctx, mp)
		assert.Equal(t, security.ForbiddenError{}, err)
	})

	testAuthorization(t, PartialAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		delete(mp, prmPathRealm)
		_, err := auth.GetEvents(ctx, mp)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetEventsSummaryAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEventsSummary(ctx).Return(api.EventSummaryRepresentation{}, nil).Times(1)
		_, err := auth.GetEventsSummary(ctx)
		assert.Nil(t, err)
	})
}

func TestGetActionsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetActions(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetEventsSummaryDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetEventsSummary(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetUserEventsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization(), func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetUserEvents(ctx, mp).Return(api.AuditEventsRepresentation{}, nil).Times(1)
		_, err := auth.GetUserEvents(ctx, mp)
		assert.Nil(t, err)
	})
}

func TestGetUserEventsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth Component, mockComponent *mock.Component, ctx context.Context, mp map[string]string) {
		_, err := auth.GetUserEvents(ctx, mp)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
