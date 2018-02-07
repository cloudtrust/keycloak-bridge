package event

import (
	"context"

	"github.com/cloudtrust/keycloak-bridge/pkg/event/flatbuffer/fb"
)

/*
Mock MuxService for Testing
*/
type mockMuxComponent struct{}

func (u *mockMuxComponent) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, nil
}

/*
Mock AdminEventService for Testing
*/
type mockAdminComponent struct{}

func (u *mockAdminComponent) AdminEvent(ctx context.Context, adminEvent *fb.AdminEvent) (interface{}, error) {
	return "", nil
}

/*
Mock EventService for Testing
*/
type mockComponent struct{}

func (u *mockComponent) Event(ctx context.Context, event *fb.Event) (interface{}, error) {
	return "", nil
}
