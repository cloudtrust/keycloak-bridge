package event

import (
	"context"

	events "github.com/cloudtrust/keycloak-bridge/services/events/transport/flatbuffers/fb"
)

/*
Mock MuxService for Testing
*/
type mockMuxService struct{}

func (u *mockMuxService) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, nil
}

/*
Mock AdminEventService for Testing
*/
type mockAdminEventService struct{}

func (u *mockAdminEventService) AdminEvent(ctx context.Context, adminEvent *events.AdminEvent) (interface{}, error) {
	return "", nil
}

/*
Mock EventService for Testing
*/
type mockEventService struct{}

func (u *mockEventService) Event(ctx context.Context, event *events.Event) (interface{}, error) {
	return "", nil
}
