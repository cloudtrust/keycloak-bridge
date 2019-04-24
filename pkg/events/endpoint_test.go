package events

//go:generate mockgen -destination=./mock/component.go -package=mock -mock_names=EventsComponent=EventsComponent github.com/cloudtrust/keycloak-bridge/pkg/events EventsComponent

import (
	"context"
	"testing"

	api "github.com/cloudtrust/keycloak-bridge/api/events"
	"github.com/cloudtrust/keycloak-bridge/pkg/events/mock"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMakeGetEventsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockEventsComponent = mock.NewEventsComponent(mockCtrl)

	var e = MakeGetEventsEndpoint(mockEventsComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockEventsComponent.EXPECT().GetEvents(ctx, req).Return([]api.AuditRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetEventsSummaryEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockEventsComponent = mock.NewEventsComponent(mockCtrl)

	var e = MakeGetEventsSummaryEndpoint(mockEventsComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockEventsComponent.EXPECT().GetEventsSummary(ctx).Return(api.EventSummaryRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetUserEventsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockEventsComponent = mock.NewEventsComponent(mockCtrl)

	var e = MakeGetUserEventsEndpoint(mockEventsComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockEventsComponent.EXPECT().GetUserEvents(ctx, req).Return([]api.AuditRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
