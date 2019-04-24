package events

//go:generate mockgen -destination=./mock/logging.go -package=mock -mock_names=Logger=Logger github.com/go-kit/kit/log Logger
//go:generate mockgen -destination=./mock/keycloak_client.go -package=mock -mock_names=KeycloakClient=KeycloakClient github.com/cloudtrust/keycloak-bridge/internal/security KeycloakClient

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/internal/security"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	kc "github.com/cloudtrust/keycloak-client"
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

func testAuthorization(t *testing.T, jsonAuthz string, tester func(ec EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string)) {
	var mockCtrl = gomock.NewController(t)
	mockKeycloakClient := mock.NewKeycloakClient(mockCtrl)
	var authorizations, err = security.NewAuthorizationManager(mockKeycloakClient, jsonAuthz)
	assert.Nil(t, err)

	mockLogger := mock.NewLogger(mockCtrl)
	mockEventsComponent := mock.NewEventsComponent(mockCtrl)

	var authorizationMW = MakeAuthorizationManagementComponentMW(mockLogger, authorizations)(mockEventsComponent)

	var accessToken = "TOKEN=="
	var groups = []string{"toe"}
	var realmName = "master"
	var userID = "123-456-789"
	var groupID = "123-789-454"
	var groupName = "titi"

	var ctx = context.WithValue(context.Background(), "access_token", accessToken)
	ctx = context.WithValue(ctx, "groups", groups)
	ctx = context.WithValue(ctx, "realm", realmName)
	var group = kc.GroupRepresentation{
		Id:   &groupID,
		Name: &groupName,
	}

	mp := make(map[string]string)
	mp["realm"] = realmName
	mp["userID"] = userID

	mockKeycloakClient.EXPECT().GetGroupsOfUser(accessToken, realmName, userID).Return([]kc.GroupRepresentation{group}, nil).AnyTimes()

	tester(authorizationMW, mockEventsComponent, ctx, mp)
}

func TestGetEventsAllow(t *testing.T) {
	testAuthorization(t, WithAuthorization, func(auth EventsComponent, mockComponent *mock.EventsComponent, ctx context.Context, mp map[string]string) {
		mockComponent.EXPECT().GetEvents(ctx, mp).Return([]api.AuditRepresentation{}, nil).Times(1)
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
		mockComponent.EXPECT().GetUserEvents(ctx, mp).Return([]api.AuditRepresentation{}, nil).Times(1)
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
