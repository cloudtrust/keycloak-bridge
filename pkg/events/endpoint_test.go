package events

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

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetEventsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockComponent.EXPECT().GetEvents(ctx, req).Return(api.AuditEventsRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetEventsSummaryEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetEventsSummaryEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockComponent.EXPECT().GetEventsSummary(ctx).Return(api.EventSummaryRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}

func TestMakeGetUserEventsEndpoint(t *testing.T) {
	var mockCtrl = gomock.NewController(t)
	defer mockCtrl.Finish()

	var mockComponent = mock.NewComponent(mockCtrl)

	var e = MakeGetUserEventsEndpoint(mockComponent)

	var ctx = context.Background()
	var req = make(map[string]string)

	mockComponent.EXPECT().GetUserEvents(ctx, req).Return(api.AuditEventsRepresentation{}, nil).Times(1)
	var res, err = e(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
}
