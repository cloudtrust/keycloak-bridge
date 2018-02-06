package event

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"
)

func TestErrorMiddlewareComponents_LoggingErrorMiddleware(t *testing.T) {
	var mockMuxService MuxService = &mockMuxServiceErr{}
	var calledLog = false
	var calledSentry = false
	var mockLogger log.Logger = &mockLogger{Called: &calledLog}
	var mockSentry sentryClient = &mockSentry{Called: &calledSentry}

	var m = MakeServiceErrorMiddleware(mockLogger, mockSentry)(mockMuxService)
	m.Event(nil, "test", nil)
	assert.True(t, calledLog)
	assert.True(t, calledSentry)
}

/*
Mock MuxService returning an error for testing Sentry
*/
type mockMuxServiceErr struct{}

type MyError struct {
	When time.Time
	What string
}

func (e MyError) Error() string {
	return fmt.Sprintf("%v: %v", e.When, e.What)
}

func (u *mockMuxServiceErr) Event(ctx context.Context, eventType string, obj []byte) (interface{}, error) {
	return eventType, MyError{time.Now(), "Error for Sentry"}
}
