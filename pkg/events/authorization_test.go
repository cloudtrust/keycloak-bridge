package events

import (
	"context"
	"testing"

	cs "github.com/cloudtrust/common-service"
	"github.com/cloudtrust/common-service/security"
	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/go-kit/kit/log"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	WithoutAuthorization = `{}`
	WithAuthorization    = `{
		"master": {
			"toe": {
				"EV_GetEvents": {"*": {"*": {} }},
				"EV_GetEventsSummary": {"*": {"*": {} }},
				"EV_GetUserEvents": {"*": {"*": {} }}
			}
		}
	}`
)

func testAuthorization(t *testing.T, jsonAuthz string, tester func(EventsComponent, *mock.EventsComponent, context.Context, map[string]string)) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()
	var mockLogger = log.NewNopLogger()

	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, mockLogger, jsonAuthz)
	assert.Nil(t, err)

	mockEventsComponent := mock.NewEventsComponent(mockCtrl)

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
	mp["realm"] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupNamesOfUser(accessToken, realmName, userID).Return([]string{groupName}, nil).AnyTimes()

	tester(authorizationMW, mockEventsComponent, ctx, mp)
}

func TestGetEventsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEvents(ctx, mp).Return(api.AuditEventsRepresentation{}, nil).Times(1)
		_, err := auth.GetEvents(ctx, mp)
		assert.Nil(t, err)
	})
}

func TestGetEventsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		_, err := auth.GetEvents(ctx, mp)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetEventsSummaryAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEventsSummary(ctx).Return(api.EventSummaryRepresentation{}, nil).Times(1)
		_, err := auth.GetEventsSummary(ctx)
		assert.Nil(t, err)
	})
}

func TestGetEventsSummaryDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		_, err := auth.GetEventsSummary(ctx)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}

func TestGetUserEventsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetUserEvents(ctx, mp).Return(api.AuditEventsRepresentation{}, nil).Times(1)
		_, err := auth.GetUserEvents(ctx, mp)
		assert.Nil(t, err)
	})
}

func TestGetUserEventsDeny(t *testing.T) {
	testAuthorization(t, WithoutAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		_, err := auth.GetUserEvents(ctx, mp)
		assert.Equal(t, security.ForbiddenError{}, err)
	})
}
